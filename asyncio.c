/******************************************************************************
* Copyright (C) 2013 - 2014 Andreas Öman
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
#include <fcntl.h>
#include <sys/time.h>
#include <sys/param.h>
#include <netdb.h>
#include <assert.h>
#include <stdlib.h>
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/epoll.h>

#include "queue.h"
#include "asyncio.h"
#include "trace.h"
#include "talloc.h"
#include "sock.h"

LIST_HEAD(asyncio_timer_list, asyncio_timer);
LIST_HEAD(asyncio_worker_list, asyncio_worker);

static struct asyncio_timer_list asyncio_timers;

static int asyncio_pipe[2];

static int epfd;

static int asyncio_dns_worker;
static struct asyncio_worker_list asyncio_workers;


static pthread_t asyncio_tid;

/**
 *
 */
typedef struct asyncio_worker {
  LIST_ENTRY(asyncio_worker) link;
  void (*fn)(void);
  int id;
  int pending;
} asyncio_worker_t;

static pthread_mutex_t asyncio_worker_mutex;

/**
 *
 */
static void
set_nonblocking(int fd, int on)
{
  int flags = fcntl(fd, F_GETFL);
  if(on) {
    flags |= O_NONBLOCK;
  } else {
    flags &= ~O_NONBLOCK;
  }
  fcntl(fd, F_SETFL, flags);
}




/**
 *
 */
static void
setup_socket(int fd)
{
  int val;

  val = 1;
  setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &val, sizeof(val));
  
#ifdef TCP_KEEPIDLE
  val = 30;
  setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &val, sizeof(val));
#endif

#ifdef TCP_KEEPINVL
  val = 15;
  setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &val, sizeof(val));
#endif

#ifdef TCP_KEEPCNT
  val = 5;
  setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &val, sizeof(val));
#endif

  //  val = 1;
  //  setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &val, sizeof(val));

  set_nonblocking(fd, 1);
}



/**
 *
 */
void
asyncio_wakeup_worker(int id)
{
  char x = id;
  while(1) {
    int r = write(asyncio_pipe[1], &x, 1);
    if(r == 1)
      return;

    if(r == -1 && errno == EINTR)
      continue;

    fprintf(stderr, "Pipe problems\n");
    break;
  }
}


/**
 *
 */
void
asyncio_timer_init(asyncio_timer_t *at, void (*fn)(void *opaque),
		   void *opaque)
{
  at->at_fn = fn;
  at->at_opaque = opaque;
  at->at_expire = 0;
}


/**
 *
 */
static int
at_compar(const asyncio_timer_t *a, const asyncio_timer_t *b)
{
  if(a->at_expire < b->at_expire)
    return -1;
  return 1;
}


/**
 *
 */
void
asyncio_timer_arm(asyncio_timer_t *at, int64_t expire)
{
  if(at->at_expire)
    LIST_REMOVE(at, at_link);

  at->at_expire = expire;
  LIST_INSERT_SORTED(&asyncio_timers, at, at_link, at_compar);
}


/**
 *
 */
void
asyncio_timer_disarm(asyncio_timer_t *at)
{
  if(at->at_expire) {
    LIST_REMOVE(at, at_link);
    at->at_expire = 0;
  }
}


/**
 *
 */
static void
mod_poll_flags(async_fd_t *af, int set, int clr)
{
  struct epoll_event e;
  int f = (af->af_epoll_flags | set) & ~clr;

  if(f == af->af_epoll_flags)
    return;

  assert(af->af_fd != -1);


  e.data.ptr = af;
  e.events = f;

  int op;
  if(!f) {
    op =  EPOLL_CTL_DEL;
  } else if(!af->af_epoll_flags) {
    op =  EPOLL_CTL_ADD;
  } else {
    op =  EPOLL_CTL_MOD;
  }

  int r = epoll_ctl(epfd, op, af->af_fd, &e);

  if(r) {
    fprintf(stderr, "epoll_ctl(%d, %d, %x) -- %s\n",
	    op, af->af_fd, e.events, strerror(errno));
  }

  af->af_epoll_flags = f;
}



/**
 *
 */
static async_fd_t *
async_fd_create(int fd, int flags)
{
  async_fd_t *af = calloc(1, sizeof(async_fd_t));
  af->af_fd = fd;
  atomic_set(&af->af_refcount, 1);
  htsbuf_queue_init(&af->af_sendq, INT32_MAX);
  htsbuf_queue_init(&af->af_recvq, INT32_MAX);
  mod_poll_flags(af, flags, 0);
  return af;
}


/**
 *
 */
static void
async_fd_release(async_fd_t *af)
{
  if(atomic_dec(&af->af_refcount))
    return;

  assert(af->af_dns_req == NULL);

  asyncio_timer_disarm(&af->af_timer);

  if(af->af_fd != -1)
    close(af->af_fd);

  if(af->af_flags & AF_SENDQ_MUTEX)
    pthread_mutex_destroy(&af->af_sendq_mutex);

  htsbuf_queue_flush(&af->af_sendq);
  htsbuf_queue_flush(&af->af_recvq);
  free(af->af_hostname);
  free(af);
}



/**
 *
 */
static void
do_write(async_fd_t *af)
{
  char tmp[1024];

  while(1) {
    int avail = htsbuf_peek(&af->af_sendq, tmp, sizeof(tmp));
    if(avail == 0) {
      // Nothing more to send
      mod_poll_flags(af, 0, EPOLLOUT);
      return;
    }

    int r = send(af->af_fd, tmp, avail, MSG_NOSIGNAL);
    if(r == 0)
      break;

    if(r == -1 && (errno == EAGAIN || errno == EINTR))
      break;

    if(r == -1) {
      mod_poll_flags(af, 0, EPOLLOUT);
      return;
    }

    htsbuf_drop(&af->af_sendq, r);
    if(r != avail)
      break;
  }

  mod_poll_flags(af, EPOLLOUT, 0);
}

static void
do_write_lock(async_fd_t *af)
{
  pthread_mutex_lock(&af->af_sendq_mutex);
  do_write(af);
  pthread_mutex_unlock(&af->af_sendq_mutex);
}


/**
 *
 */
static void
do_read(async_fd_t *af)
{
  char tmp[1024];
  while(1) {
    int r = read(af->af_fd, tmp, sizeof(tmp));
    if(r == 0) {
      af->af_error(af->af_opaque, ECONNRESET);
      return;
    }

    if(r == -1 && (errno == EAGAIN || errno == EINTR))
      break;

    if(r == -1) {
      af->af_error(af->af_opaque, errno);
      return;
    }

    htsbuf_append(&af->af_recvq, tmp, r);
  }

  af->af_bytes_avail(af->af_opaque, &af->af_recvq);
}



/**
 *
 */
static void
do_accept(async_fd_t *af)
{
  struct sockaddr_in remote, local;
  socklen_t slen;

  slen = sizeof(struct sockaddr_in);

  int fd = libsvc_accept(af->af_fd, (struct sockaddr *)&remote, &slen);
  if(fd == -1) {
    perror("accept");
    return;
  }

  setup_socket(fd);

  slen = sizeof(struct sockaddr_in);
  if(getsockname(fd, (struct sockaddr *)&local, &slen)) {
    close(fd);
    return;
  }

  if(af->af_accept(af->af_opaque, fd,
                   (struct sockaddr *)&remote,
                   (struct sockaddr *)&local)) {
    close(fd);
  }
}


/**
 *
 */
static void *
asyncio_loop(void *aux)
{
  struct epoll_event ev[32];
  int r, i;

  while(1) {
    talloc_cleanup();

    int64_t now = asyncio_now();

    asyncio_timer_t *at;
    while((at = LIST_FIRST(&asyncio_timers)) != NULL && at->at_expire <= now) {
      LIST_REMOVE(at, at_link);
      at->at_expire = 0;
      at->at_fn(at->at_opaque);
    }

    int timeout = INT32_MAX;
  
    if((at = LIST_FIRST(&asyncio_timers)) != NULL)
      timeout = MIN(timeout, (at->at_expire - now + 999) / 1000);

    if(timeout == INT32_MAX)
      timeout = -1;

    r = epoll_wait(epfd, ev, sizeof(ev) / sizeof(ev[0]), timeout);
    if(r == -1) {
      if(errno == EINTR)
        continue;

      perror("tcp_server: epoll_wait");
      usleep(100000);
      continue;
    }

    for(i = 0; i < r; i++) {
      async_fd_t *af = ev[i].data.ptr;
      atomic_inc(&af->af_refcount);
    }

    for(i = 0; i < r; i++) {
      async_fd_t *af = ev[i].data.ptr;

      if(ev[i].events & (EPOLLHUP | EPOLLERR) && af->af_pollerr != NULL) {
	af->af_pollerr(af);
	continue;
      }

      if(ev[i].events & EPOLLHUP) {
        if(af->af_error != NULL)
          af->af_error(af->af_opaque, ECONNRESET);
        continue;
      }

      if(ev[i].events & EPOLLERR) {
        if(af->af_error != NULL)
          af->af_error(af->af_opaque, ENOTCONN);
        continue;
      }

      if(ev[i].events & EPOLLOUT) {
	af->af_pollout(af);
      }

      if(ev[i].events & EPOLLIN) {
	af->af_pollin(af);
      }
    }


    for(i = 0; i < r; i++) {
      async_fd_t *af = ev[i].data.ptr;
      async_fd_release(af);
    }
  }
  return NULL;
}


/**
 *
 */
void
asyncio_close(async_fd_t *af)
{
  assert(af->af_fd != -1);

  asyncio_timer_disarm(&af->af_timer);

  mod_poll_flags(af, 0, -1);

  close(af->af_fd);
  af->af_fd = -1;
  async_fd_release(af);
}


/**
 *
 */
void
asyncio_shutdown(async_fd_t *af)
{
  assert(af->af_fd != -1);

  asyncio_timer_disarm(&af->af_timer);

  shutdown(af->af_fd, SHUT_RD);

  mod_poll_flags(af, 0, -1);
}


/**
 *
 */
void
asyncio_send(async_fd_t *af, const void *buf, size_t len, int cork)
{
  if(af->af_flags & AF_SENDQ_MUTEX)
    pthread_mutex_lock(&af->af_sendq_mutex);

  htsbuf_append(&af->af_sendq, buf, len);
  if(af->af_fd != -1 && !cork)
    do_write(af);

  if(af->af_flags & AF_SENDQ_MUTEX)
    pthread_mutex_unlock(&af->af_sendq_mutex);
}


/**
 *
 */
void
asyncio_sendq(async_fd_t *af, htsbuf_queue_t *q, int cork)
{
  if(af->af_flags & AF_SENDQ_MUTEX)
    pthread_mutex_lock(&af->af_sendq_mutex);

  htsbuf_appendq(&af->af_sendq, q);
  if(af->af_fd != -1 && !cork)
    do_write(af);

  if(af->af_flags & AF_SENDQ_MUTEX)
    pthread_mutex_unlock(&af->af_sendq_mutex);
}


/**
 *
 */
async_fd_t *
asyncio_bind(const char *bindaddr, int port,
             asyncio_accept_cb_t *cb,
             void *opque)
{
  int fd, ret;
  int one = 1;
  struct sockaddr_in s;

  fd = libsvc_socket(AF_INET, SOCK_STREAM, 0);
  if(fd == -1)
    return NULL;

  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(int));

  setup_socket(fd);

  memset(&s, 0, sizeof(s));
  s.sin_family = AF_INET;
  s.sin_port = htons(port);
  if(bindaddr != NULL)
    s.sin_addr.s_addr = inet_addr(bindaddr);

  ret = bind(fd, (struct sockaddr *)&s, sizeof(s));
  if(ret < 0) {
    int x = errno;
    trace(LOG_ERR, "Unable to bind %s:%d -- %s", 
          bindaddr ?: "0.0.0.0", port, strerror(errno));
    close(fd);
    errno = x;
    return NULL;
  }

  listen(fd, 100);

  async_fd_t *af = async_fd_create(fd, EPOLLIN);
  af->af_pollin = &do_accept;
  af->af_accept = cb;
  return af;
}


/**
 *
 */
async_fd_t *
asyncio_stream(int fd,
	       asyncio_read_cb_t *read,
	       asyncio_error_cb_t *err,
	       void *opaque)
{
  setup_socket(fd);
  async_fd_t *af = async_fd_create(fd, EPOLLIN);
  af->af_pollin  = &do_read;
  af->af_pollout = &do_write;
  af->af_bytes_avail = read;
  af->af_error = err;
  af->af_opaque = opaque;
  return af;
}


/**
 *
 */
async_fd_t *
asyncio_stream_mt(int fd,
                  asyncio_read_cb_t *read,
                  asyncio_error_cb_t *err,
                  void *opaque)
{
  setup_socket(fd);
  async_fd_t *af = async_fd_create(fd, 0);

  af->af_flags = AF_SENDQ_MUTEX;
  pthread_mutex_init(&af->af_sendq_mutex, NULL);

  af->af_pollin  = &do_read;
  af->af_pollout = &do_write_lock;
  af->af_bytes_avail = read;
  af->af_error = err;
  af->af_opaque = opaque;
  return af;
}


/**
 *
 */
void
asyncio_enable_read(async_fd_t *fd)
{
  mod_poll_flags(fd, EPOLLIN, 0);
}


/**
 *
 */
static void
con_send_err(async_fd_t *af, const char *msg)
{
  int retry = af->af_connect(af->af_opaque, msg);
  if(retry == 0) {
    async_fd_release(af);
  } else {
    asyncio_timer_arm(&af->af_timer, asyncio_now() + retry * 1000);
  }
}


/**
 *
 */
static void
connection_established(async_fd_t *af)
{
  asyncio_timer_disarm(&af->af_timer);
  af->af_pollerr = NULL;

  af->af_pollin  = &do_read;
  af->af_pollout = &do_write;
  mod_poll_flags(af, EPOLLIN, 0);

  af->af_connect(af->af_opaque, NULL);

  do_write(af);
}


/**
 *
 */
static void
check_connect_status(async_fd_t *af)
{
  int err;
  socklen_t errlen = sizeof(int);
    
  getsockopt(af->af_fd, SOL_SOCKET, SO_ERROR, (void *)&err, &errlen);
  if(err == 0)
    return connection_established(af);

  mod_poll_flags(af, 0, -1);
  close(af->af_fd);
  af->af_fd = -1;
  char errmsg[256];
  snprintf(errmsg, sizeof(errmsg), "%s", strerror(err));
  con_send_err(af, errmsg);
}


/**
 *
 */
static void
initiate_connect(async_fd_t *af, const struct sockaddr_in *addr)
{
  int fd;

  struct sockaddr_in sin = *addr;
  sin.sin_port = htons(af->af_port);

  if((fd = libsvc_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
    con_send_err(af, "Unable to create socket");
    return;
  }

  setup_socket(fd);

  int r = connect(fd, (struct sockaddr *)&sin, sizeof(struct sockaddr_in));

  assert(af->af_fd == -1);

  if(!r) {
    af->af_fd = fd;
    return connection_established(af);
  }

  if(errno == EINPROGRESS) {
    af->af_fd = fd;
    af->af_pollout = check_connect_status;
    af->af_pollerr = check_connect_status;
    mod_poll_flags(af, EPOLLOUT, 0);
    return;
  }

  close(fd);
  char errmsg[256];
  snprintf(errmsg, sizeof(errmsg), "%s", strerror(errno));
  con_send_err(af, errmsg);
  return;
}


/**
 *
 */
static void
connect_dns_cb(void *opaque, int status, const void *data)
{
  async_fd_t *af = opaque;
  af->af_dns_req = NULL;

  switch(status) {
  case ASYNCIO_DNS_STATUS_COMPLETED:
    initiate_connect(af, data);
    return;

  case ASYNCIO_DNS_STATUS_FAILED:
    con_send_err(af, data);
    return;

  default:
    abort();
  }
}

/**
 *
 */
static void
connect_timeout(void *opaque)
{
  async_fd_t *af = opaque;

  if(af->af_dns_req != NULL) {
    // Still trying to resolve DNS
    asyncio_dns_cancel(af->af_dns_req);
    af->af_dns_req = NULL;
    con_send_err(af, "Timeout during DNS lookup");
    return;
  }

  if(af->af_fd != -1) {
    mod_poll_flags(af, 0, -1);
    close(af->af_fd);
    af->af_fd = -1;
    con_send_err(af, "Connection timed out");
  }

  assert(af->af_dns_req == NULL);

  af->af_dns_req = asyncio_dns_lookup_host(af->af_hostname,
					   connect_dns_cb, af);
}



/**
 *
 */
async_fd_t *
asyncio_connect(const char *hostname,
		int port, int timeout,
		asyncio_connect_cb_t *cb,
		asyncio_read_cb_t *read,
		asyncio_error_cb_t *err,
		void *opaque)
{
  assert(cb != NULL);
  assert(read != NULL);
  assert(err != NULL);

  async_fd_t *af = async_fd_create(-1, 0);
  af->af_opaque = opaque;

  af->af_port        = port;
  af->af_hostname    = strdup(hostname);

  af->af_connect     = cb;
  af->af_bytes_avail = read;
  af->af_error       = err;

  asyncio_timer_init(&af->af_timer, connect_timeout, af);
  asyncio_timer_arm(&af->af_timer, asyncio_now() + timeout * 1000);
  af->af_dns_req = asyncio_dns_lookup_host(hostname, connect_dns_cb, af);
  return af;
}


/**
 *
 */
void
asyncio_reconnect(async_fd_t *af, int delay)
{
  printf("Reconnect to %s\n", af->af_hostname);
  if(af->af_fd == -1) {
    printf("Reconnect on non-open socket!?\n");
    return;
  }
  assert(af->af_dns_req == NULL);

  mod_poll_flags(af, 0, -1);
  close(af->af_fd);
  af->af_fd = -1;

  asyncio_timer_arm(&af->af_timer, asyncio_now() + delay * 1000);
}


/**
 * DNS handling
 */

static pthread_mutex_t asyncio_dns_mutex;
TAILQ_HEAD(asyncio_dns_req_queue, asyncio_dns_req);
static struct asyncio_dns_req_queue asyncio_dns_pending;
static struct asyncio_dns_req_queue asyncio_dns_completed;


struct asyncio_dns_req {
  TAILQ_ENTRY(asyncio_dns_req) adr_link;
  char *adr_hostname;
  void *adr_opaque;
  void (*adr_cb)(void *opaque, int status, const void *data);

  int adr_status;
  const void *adr_data;
  const char *adr_errmsg;
  struct sockaddr_in adr_addr;
};


static int adr_resolver_running;

/**
 *
 */
static int
adr_resolve(asyncio_dns_req_t *adr)
{
  struct hostent *hp;
  char *tmphstbuf;
  int herr;
#if !defined(__APPLE__)
  struct hostent hostbuf;
  size_t hstbuflen;
  int res;
#endif

  const char *hostname = adr->adr_hostname;

#if defined(__APPLE__)
  herr = 0;
  tmphstbuf = NULL; /* free NULL is a nop */
  /* TODO: AF_INET6 */
  hp = gethostbyname(hostname);
  if(hp == NULL)
    herr = h_errno;
#else
  hstbuflen = 1024;
  tmphstbuf = malloc(hstbuflen);

  while((res = gethostbyname_r(hostname, &hostbuf, tmphstbuf, hstbuflen,
			       &hp, &herr)) == ERANGE) {
    hstbuflen *= 2;
    tmphstbuf = realloc(tmphstbuf, hstbuflen);
  }
#endif
  if(herr != 0) {
    switch(herr) {
    case HOST_NOT_FOUND:
      adr->adr_errmsg = "Unknown host";
      break;

    case NO_ADDRESS:
      adr->adr_errmsg = 
	"The requested name is valid but does not have an IP address";
      break;
      
    case NO_RECOVERY:
      adr->adr_errmsg = "A non-recoverable name server error occurred";
      break;
      
    case TRY_AGAIN:
      adr->adr_errmsg =
	"A temporary error occurred on an authoritative name server";
      break;
      
    default:
      adr->adr_errmsg = "Unknown error";
      break;
    }

    free(tmphstbuf);
    return -1;

  } else if(hp == NULL) {
    adr->adr_errmsg = "Resolver internal error";
    free(tmphstbuf);
    return -1;
  }

  switch(hp->h_addrtype) {
  case AF_INET:
    adr->adr_addr.sin_family = AF_INET;
    memcpy(&adr->adr_addr.sin_addr, hp->h_addr_list[0], sizeof(struct in_addr));
    break;

  default:
    adr->adr_errmsg = "Resolver internal error";
    free(tmphstbuf);
    return -1;
  }

  free(tmphstbuf);
  return 0;
}

/**
 *
 */
static void *
adr_resolver(void *aux)
{
  asyncio_dns_req_t *adr;
  pthread_mutex_lock(&asyncio_dns_mutex);
  while((adr = TAILQ_FIRST(&asyncio_dns_pending)) != NULL) {
    TAILQ_REMOVE(&asyncio_dns_pending, adr, adr_link);

    pthread_mutex_unlock(&asyncio_dns_mutex);

    
    if(adr_resolve(adr)) {
      adr->adr_status = ASYNCIO_DNS_STATUS_FAILED;
      adr->adr_data = adr->adr_errmsg;
    } else {
      adr->adr_status = ASYNCIO_DNS_STATUS_COMPLETED;
      adr->adr_data = &adr->adr_addr;
    }
    pthread_mutex_lock(&asyncio_dns_mutex);
    TAILQ_INSERT_TAIL(&asyncio_dns_completed, adr, adr_link);
    asyncio_wakeup_worker(asyncio_dns_worker);
  }

  adr_resolver_running = 0;
  pthread_mutex_unlock(&asyncio_dns_mutex);
  return NULL;
}


/**
 *
 */
void
asyncio_dns_cancel(asyncio_dns_req_t *r)
{
  assert(pthread_self() == asyncio_tid);
  r->adr_cb = NULL;
}


/**
 *
 */
asyncio_dns_req_t *
asyncio_dns_lookup_host(const char *hostname, 
			void (*cb)(void *opaque,
				   int status,
				   const void *data),
			void *opaque)
{
  asyncio_dns_req_t *adr;

  adr = calloc(1, sizeof(asyncio_dns_req_t));
  adr->adr_hostname = strdup(hostname);
  adr->adr_cb = cb;
  adr->adr_opaque = opaque;
  
  pthread_mutex_lock(&asyncio_dns_mutex);
  TAILQ_INSERT_TAIL(&asyncio_dns_pending, adr, adr_link);
  if(!adr_resolver_running) {
    adr_resolver_running = 1;

    pthread_t tid;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_create(&tid, &attr, adr_resolver, NULL);
    pthread_attr_destroy(&attr);
  }
  pthread_mutex_unlock(&asyncio_dns_mutex);
  return adr;
}


/**
 * Return async DNS requests to caller
 */
static void
adr_deliver_cb(void)
{
  asyncio_dns_req_t *adr;

  pthread_mutex_lock(&asyncio_dns_mutex);

  while((adr = TAILQ_FIRST(&asyncio_dns_completed)) != NULL) {
    TAILQ_REMOVE(&asyncio_dns_completed, adr, adr_link);
    pthread_mutex_unlock(&asyncio_dns_mutex);
    if(adr->adr_cb != NULL)
      adr->adr_cb(adr->adr_opaque, adr->adr_status, adr->adr_data);

    free(adr->adr_hostname);
    free(adr);
    pthread_mutex_lock(&asyncio_dns_mutex);
  } 
  pthread_mutex_unlock(&asyncio_dns_mutex);
}

/**
 *
 */
static void
asyncio_handle_pipe(async_fd_t *af)
{
  char x;
  if(read(asyncio_pipe[0], &x, 1) != 1)
    return;

  asyncio_worker_t *aw;
  pthread_mutex_lock(&asyncio_worker_mutex);

  LIST_FOREACH(aw, &asyncio_workers, link)
    if(aw->id == x)
      break;

  pthread_mutex_unlock(&asyncio_worker_mutex);

  if(aw != NULL)
    aw->fn();
}


/**
 *
 */
int
asyncio_add_worker(void (*fn)(void))
{
  asyncio_worker_t *aw = calloc(1, sizeof(asyncio_worker_t));

  aw->fn = fn;

  static  int generator;

  pthread_mutex_lock(&asyncio_worker_mutex);
  generator++;
  aw->id = generator;
  LIST_INSERT_HEAD(&asyncio_workers, aw, link);
  pthread_mutex_unlock(&asyncio_worker_mutex);
  return aw->id;
}



/**
 *
 */
void
asyncio_init(void)
{
  if(pipe(asyncio_pipe)) {
    perror("pipe");
    return;
  }

  TAILQ_INIT(&asyncio_dns_pending);
  TAILQ_INIT(&asyncio_dns_completed);

  epfd = epoll_create1(EPOLL_CLOEXEC);

  pthread_mutex_init(&asyncio_worker_mutex, NULL);

  asyncio_dns_worker = asyncio_add_worker(adr_deliver_cb);

  async_fd_t *af = async_fd_create(asyncio_pipe[0], EPOLLIN);
  af->af_pollin = &asyncio_handle_pipe;

  pthread_create(&asyncio_tid, NULL, asyncio_loop, NULL);
}


/**
 *
 */
int64_t
asyncio_now(void)
{
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return (int64_t)tv.tv_sec * 1000000LL + tv.tv_usec;
}
