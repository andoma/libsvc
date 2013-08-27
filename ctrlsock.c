#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <pwd.h>
#include <sys/stat.h>
#include <pthread.h>

#include "htsbuf.h"
#include "trace.h"
#include "ctrlsock.h"
#include "cmd.h"

static int ctrlsock_fd;


/**
 *
 */
static void
output_callback(void *aux, const char *fmt, ...)
{
  char buf[2048];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);

  int fd = *(int *)aux;

  struct iovec iov[3];

  iov[0].iov_base = (void *)":";
  iov[0].iov_len = 1;

  iov[1].iov_base = (void *)buf;
  iov[1].iov_len = strlen(buf);

  iov[2].iov_base = (void *)"\n";
  iov[2].iov_len = 1;

  if(writev(fd, iov, 3) != iov[1].iov_len + 2) {
    trace(LOG_ERR, "Write failed on ctrl sock");
  }
}



/**
 *
 */
static int
parse_line(int fd, const char *str, const char *user)
{
  int rval;
  char tmp[32];
  switch(*str) {

  case 'X': // Execute
    rval = cmd_exec(str + 1, user, &output_callback, &fd);
    break;

  case 'C': // Complete
    rval = cmd_complete(str + 1, user, &output_callback, &fd);
    break;

  default:
    return 1;
  }
  int l = snprintf(tmp, sizeof(tmp), "%d\n", rval);
  return write(fd, tmp, l) != l;
}


/**
 *
 */
static int
parse_input(int fd, htsbuf_queue_t *q, const char *user)
{
  while(1) {
    int ll = htsbuf_find(q, 0x0a);
    if(ll == -1)
      return 0;

    char *line = alloca(ll + 1);

    htsbuf_read(q, line, ll);
    htsbuf_drop(q, 1); // Drop \n

    line[ll] = 0;
    if(parse_line(fd, line, user))
      return 1;
  }
}



/**
 *
 */
static void *
conn_thread(void *aux)
{
  int fd = (intptr_t)aux;
  struct ucred cr;
  socklen_t len = sizeof(cr);
  char buf[1024];

  if(getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cr, &len)) {
    trace(LOG_ERR, "Unable to get peer credentials -- %s",
          strerror(errno));
    close(fd);
    return NULL;
  }

  struct passwd pwd;
  struct passwd *result;

  int s = getpwuid_r(cr.uid, &pwd, buf, sizeof(buf), &result);
  if(result == NULL) {
    if(s == 0) {
      trace(LOG_ERR, "UID %d does not exist, closing", cr.uid);
    } else {
      trace(LOG_ERR, "Failed to lookup UID %d -- %s", cr.uid,
            strerror(s));
    }
    close(fd);
    return NULL;
  }

  trace(LOG_INFO,
        "Control connection from user '%s' PID:%d UID:%d GID:%d",
        pwd.pw_name, cr.pid, cr.uid, cr.gid);

  htsbuf_queue_t recvq;
  htsbuf_queue_init(&recvq, 0);

  while(1) {
    uint8_t buf[256];
    int r = read(fd, buf, sizeof(buf));
    if(r <= 0) {
      trace(LOG_INFO, "Connection lost from PID %d", cr.pid);
      break;
    }
    htsbuf_append(&recvq, buf, r);
    if(parse_input(fd, &recvq, pwd.pw_name))
      break;
  }

  htsbuf_queue_flush(&recvq);

  close(fd);
  return NULL;
}

/**
 *
 */
static void *
ctrlsock_thread(void *aux)
{
  socklen_t siz;
  struct sockaddr_un sun;
  pthread_t tid;

  while(1) {
    siz = sizeof(struct sockaddr_un);
    int fd = accept(ctrlsock_fd, (struct sockaddr *)&sun, &siz);
    if(fd == -1) {
      trace(LOG_ERR, "Unable to accept ctrl socket -- %s",
            strerror(errno));
      sleep(1);
      continue;
    }

    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_create(&tid, &attr, conn_thread, (void *)(intptr_t)fd);
    pthread_attr_destroy(&attr);
  }
  return NULL;
}


/**
 *
 */
void
ctrlsock_init(const char *ctrlsockpath)
{
  int fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if(fd == -1) {
    trace(LOG_ERR, "Unable to create ctrl socket -- %s",
          strerror(errno));
    exit(1);
  }

  struct sockaddr_un sun;

  memset(&sun, 0, sizeof(sun));

  unlink(ctrlsockpath);

  sun.sun_family = AF_UNIX;
  strcpy(sun.sun_path, ctrlsockpath);
  if(bind(fd, (struct sockaddr *)&sun, sizeof(sun))) {
    trace(LOG_ERR, "Unable to bind ctrl socket %s -- %s",
          ctrlsockpath, strerror(errno));
    exit(1);
  }

  if(listen(fd, 10)) {
    trace(LOG_ERR, "Unable to listen on ctrl socket %s -- %s",
          ctrlsockpath, strerror(errno));
    exit(1);
  }

  chmod(ctrlsockpath, 0770);

  ctrlsock_fd = fd;

  pthread_t tid;
  pthread_create(&tid, NULL, ctrlsock_thread, NULL);
}
