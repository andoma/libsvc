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
#ifdef __linux__
#include <sys/epoll.h>
#elif defined(__APPLE__)
#include <sys/event.h>
#else
#error Need poll mechanism
#endif


#include "queue.h"
#include "asyncio.h"
#include "trace.h"
#include "talloc.h"
#include "sock.h"

LIST_HEAD(asyncio_timer_list, asyncio_timer);
LIST_HEAD(asyncio_worker_list, asyncio_worker);

#define TW_TIME_SHIFT  18
#define TW_SLOTS 65536
#define TW_SLOT_MASK (TW_SLOTS - 1)

static struct asyncio_timer_list timerwheel[TW_SLOTS];
static int                timerwheel_read_pos;

static int asyncio_pipe[2];

static int epfd;

static int asyncio_dns_worker;
static int asyncio_task_worker;
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
typedef struct asyncio_task {
  TAILQ_ENTRY(asyncio_task) at_link;
  void (*at_fn)(void *aux);
  void *at_aux;
  int at_block;
} asyncio_task_t;

static pthread_mutex_t asyncio_task_mutex;
static pthread_cond_t asyncio_task_cond;
static TAILQ_HEAD(, asyncio_task) asyncio_tasks;

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
static int64_t
asyncio_get_monotime(void)
{
#if _POSIX_TIMERS > 0 && defined(_POSIX_MONOTONIC_CLOCK)
  struct timespec tv;
  clock_gettime(CLOCK_MONOTONIC, &tv);
  return (int64_t)tv.tv_sec * 1000000LL + (tv.tv_nsec / 1000);
#else
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return (int64_t)tv.tv_sec * 1000000LL + tv.tv_usec;
#endif
}


/**
 *
 */
void
asyncio_timer_arm_delta(asyncio_timer_t *at, uint64_t delta)
{
  assert(pthread_self() == asyncio_tid);

  if(at->at_expire)
    LIST_REMOVE(at, at_link);

  const int64_t now = asyncio_get_monotime();

  int64_t expire = now + delta;
  if(expire < now)
    expire = now;

  const int slot = ((expire >> TW_TIME_SHIFT) + 1) & TW_SLOT_MASK;

  at->at_expire = expire;
  LIST_INSERT_HEAD(&timerwheel[slot], at, at_link);
}


/**
 *
 */
void
asyncio_timer_disarm(asyncio_timer_t *at)
{
  assert(pthread_self() == asyncio_tid);

  if(at->at_expire) {
    LIST_REMOVE(at, at_link);
    at->at_expire = 0;
  }
}

#ifdef __linux__
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
#endif

#ifdef __APPLE__

#define EPOLLIN  0x1
#define EPOLLOUT 0x2
#define MSG_NOSIGNAL 0
#define MSG_MORE 0

/**
 *
 */
static void
mod_poll_flags(async_fd_t *af, int set, int clr)
{
  set &= ~af->af_epoll_flags;
  clr &=  af->af_epoll_flags;

  assert(af->af_fd != -1);

  struct kevent changes[2];
  int num_changes = 0;

  if(set & EPOLLIN) {
    EV_SET(&changes[0], af->af_fd, EVFILT_READ, EV_ADD, 0, 0, af);
    num_changes++;
  } else if(clr & EPOLLIN) {
    EV_SET(&changes[0], af->af_fd, EVFILT_READ, EV_DELETE, 0, 0, af);
    num_changes++;
  }

  if(set & EPOLLOUT) {
    EV_SET(&changes[num_changes], af->af_fd, EVFILT_WRITE, EV_ADD, 0, 0, af);
    num_changes++;
  } else if(clr & EPOLLOUT) {
    EV_SET(&changes[num_changes], af->af_fd, EVFILT_WRITE, EV_DELETE, 0, 0, af);
    num_changes++;
  }

  struct timespec instant = {};
  int r = kevent(epfd, changes, num_changes, NULL, 0, &instant);
  if(r == -1)
    perror("kevent() modify");

  af->af_epoll_flags = (af->af_epoll_flags | set) & ~clr;
}
#endif


/**
 *
 */
static async_fd_t *
async_fd_create(int fd, int flags)
{
  async_fd_t *af = calloc(1, sizeof(async_fd_t));
  af->af_fd = fd;
  atomic_set(&af->af_refcount, 1);
  mbuf_init(&af->af_sendq);
  mbuf_init(&af->af_recvq);
  mod_poll_flags(af, flags, 0);
  return af;
}


/**
 *
 */
void
async_fd_retain(async_fd_t *af)
{
  atomic_inc(&af->af_refcount);
}


/**
 *
 */
void
async_fd_release(async_fd_t *af)
{
  if(atomic_dec(&af->af_refcount))
    return;
  assert(af->af_dns_req == NULL);
  assert(af->af_timer.at_expire == 0);
  assert(af->af_fd == -1);

  if(af->af_flags & AF_SENDQ_MUTEX) {
    pthread_mutex_destroy(&af->af_sendq_mutex);
    pthread_cond_destroy(&af->af_sendq_cond);
  }

  mbuf_clear(&af->af_sendq);
  mbuf_clear(&af->af_recvq);
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
    int avail = mbuf_peek(&af->af_sendq, tmp, sizeof(tmp));
    if(avail == 0) {
      if(af->af_pending_shutdown) {
        shutdown(af->af_fd, 2);
      }
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

    mbuf_drop(&af->af_sendq, r);

    if(af->af_flags & AF_SENDQ_MUTEX)
      pthread_cond_signal(&af->af_sendq_cond);

    if(r != avail)
      break;
  }

  mod_poll_flags(af, EPOLLOUT, 0);
}


/**
 *
 */
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
int
asyncio_wait_send_buffer(async_fd_t *af, int size)
{
  int r = 0;
  pthread_mutex_lock(&af->af_sendq_mutex);

  while(1) {
    if(af->af_pending_error) {
      r = af->af_pending_error;
      break;
    }

    if(size > af->af_sendq.mq_size)
      break;

    pthread_cond_wait(&af->af_sendq_cond, &af->af_sendq_mutex);
  }
  pthread_mutex_unlock(&af->af_sendq_mutex);
  return r;
}


/**
 *
 */
static void
do_error(async_fd_t *af, int error)
{
  if(af->af_flags & AF_SENDQ_MUTEX) {
    pthread_mutex_lock(&af->af_sendq_mutex);
    af->af_pending_error = error;
    pthread_cond_signal(&af->af_sendq_cond);
    pthread_mutex_unlock(&af->af_sendq_mutex);
  }
  if(af->af_error != NULL)
    af->af_error(af->af_opaque, error);
  af->af_error = NULL;
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
      do_error(af, ECONNRESET);
      return;
    }

    if(r == -1 && (errno == EAGAIN || errno == EINTR))
      break;

    if(r == -1) {
      do_error(af, errno);
      return;
    }

    mbuf_append(&af->af_recvq, tmp, r);
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
static int
tw_step(void)
{
  asyncio_timer_t *at, *next;
  int64_t now = asyncio_get_monotime();
  int target_slot = (now >> TW_TIME_SHIFT) & TW_SLOT_MASK;
  int cbs = 0;
  struct asyncio_timer_list tmplist;
  LIST_INIT(&tmplist);

  while(timerwheel_read_pos != target_slot) {
    timerwheel_read_pos = (timerwheel_read_pos + 1) & TW_SLOT_MASK;

    for(at = LIST_FIRST(&timerwheel[timerwheel_read_pos]);
        at != NULL; at = next) {
      next = LIST_NEXT(at, at_link);
      if(at->at_expire <= now) {
        LIST_REMOVE(at, at_link);
        LIST_INSERT_HEAD(&tmplist, at, at_link);
      }
    }

    while((at = LIST_FIRST(&tmplist)) != NULL) {
      LIST_REMOVE(at, at_link);
      at->at_expire = 0;
      at->at_fn(at->at_opaque);
      cbs++;
    }
  }

  const int slottime = 1 << TW_TIME_SHIFT;
  int spill = now & (slottime - 1);
  return (slottime - spill) / 1000 + 1;
}


/**
 *
 */
static void *
asyncio_loop(void *aux)
{
  int r, i;

  while(1) {
    talloc_cleanup();

    int timeout = tw_step();

#ifdef __linux__

    struct epoll_event ev[256];

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
        do_error(af, ECONNRESET);
        continue;
      }

      if(ev[i].events & EPOLLERR) {
        do_error(af, ENOTCONN);
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
#endif


#ifdef __APPLE__
    struct kevent events[256];

    struct timespec ts0, *ts = NULL;
    if(timeout != -1) {
      ts0.tv_sec = timeout / 1000;
      ts0.tv_nsec = (timeout % 1000) * 1000000LL;
      ts = &ts0;
    }

    r = kevent(epfd, NULL, 0, events, sizeof(events) / sizeof(events[0]), ts);
    if(r == -1) {
      if(errno == EINTR)
        continue;
      perror("kevent() poll");
      usleep(100000);
      continue;
    }

    for(i = 0; i < r; i++) {
      async_fd_t *af = events[i].udata;
      atomic_inc(&af->af_refcount);
    }

    for(i = 0; i < r; i++) {
      async_fd_t *af = events[i].udata;
      if(events[i].filter == EVFILT_READ) {
        if(events[i].flags & EV_EOF) {
          do_error(af, ECONNRESET);
        } else {
          af->af_pollin(af);
        }
      }

      if(events[i].filter == EVFILT_WRITE) {
        if(events[i].flags & EV_EOF) {
          do_error(af, ECONNRESET);
        } else {
          af->af_pollout(af);
        }
      }
    }

    for(i = 0; i < r; i++) {
      async_fd_t *af = events[i].udata;
      async_fd_release(af);
    }

#endif
  }
  return NULL;
}


/**
 *
 */
void
asyncio_close(async_fd_t *af)
{
  assert(pthread_self() == asyncio_tid);

  asyncio_timer_disarm(&af->af_timer);

  if(af->af_flags & AF_SENDQ_MUTEX)
    pthread_mutex_lock(&af->af_sendq_mutex);

  if(af->af_fd != -1) {
    mod_poll_flags(af, 0, -1);
    close(af->af_fd);
    af->af_fd = -1;
  }

  if(af->af_flags & AF_SENDQ_MUTEX)
    pthread_mutex_unlock(&af->af_sendq_mutex);
  else
    async_fd_release(af);
}


/**
 *
 */
void
asyncio_shutdown(async_fd_t *af)
{
  if(af->af_flags & AF_SENDQ_MUTEX)
    pthread_mutex_lock(&af->af_sendq_mutex);

  if(af->af_fd != -1) {

    if(af->af_sendq.mq_size) {
      af->af_pending_shutdown = 1;
    } else {
      shutdown(af->af_fd, 2);
    }
  }

  if(af->af_flags & AF_SENDQ_MUTEX)
    pthread_mutex_unlock(&af->af_sendq_mutex);
}


/**
 *
 */
int
asyncio_send(async_fd_t *af, const void *buf, size_t len, int cork)
{
  int rval = 0;
  if(af->af_flags & AF_SENDQ_MUTEX)
    pthread_mutex_lock(&af->af_sendq_mutex);

  if(af->af_fd != -1) {
    mbuf_append(&af->af_sendq, buf, len);

    if(!cork)
      do_write(af);
  } else {
    rval = -1;
  }

  if(af->af_flags & AF_SENDQ_MUTEX)
    pthread_mutex_unlock(&af->af_sendq_mutex);
  return rval;
}


/**
 *
 */
int
asyncio_send_with_hdr(async_fd_t *af,
                      const void *hdr_buf, size_t hdr_len,
                      const void *buf, size_t len,
                      int cork)
{
  int rval = 0;
  if(af->af_flags & AF_SENDQ_MUTEX)
    pthread_mutex_lock(&af->af_sendq_mutex);

  if(af->af_fd != -1) {
    int qempty = af->af_sendq.mq_size == 0;

    if(!cork && qempty) {
      int r = send(af->af_fd, hdr_buf, hdr_len, MSG_NOSIGNAL | MSG_MORE);
      if(r > 0) {
        hdr_buf += r;
        hdr_len -= r;
      }
    }

    if(hdr_len > 0) {
      mbuf_append(&af->af_sendq, hdr_buf, hdr_len);
      qempty = 0;
    }

    if(!cork && qempty) {
      int r = send(af->af_fd, buf, len, MSG_NOSIGNAL);
      if(r > 0) {
        buf += r;
        len -= r;
      }
    }

    if(len > 0) {
      mbuf_append(&af->af_sendq, buf, len);
      qempty = 0;
    }

    if(!cork)
      do_write(af);
  } else {
    rval = -1;
  }

  if(af->af_flags & AF_SENDQ_MUTEX)
    pthread_mutex_unlock(&af->af_sendq_mutex);
  return rval;
}


/**
 *
 */
int
asyncio_sendq(async_fd_t *af, mbuf_t *q, int cork)
{
  int rval = 0;
  if(af->af_flags & AF_SENDQ_MUTEX)
    pthread_mutex_lock(&af->af_sendq_mutex);

  if(af->af_fd != -1) {
    mbuf_appendq(&af->af_sendq, q);
    if(!cork)
      do_write(af);
  } else {
    mbuf_clear(q);
    rval = 1;
  }

  if(af->af_flags & AF_SENDQ_MUTEX)
    pthread_mutex_unlock(&af->af_sendq_mutex);
  return rval;
}


/**
 *
 */
void
asyncio_send_lock(async_fd_t *af)
{
  if(af->af_flags & AF_SENDQ_MUTEX)
    pthread_mutex_lock(&af->af_sendq_mutex);
}


/**
 *
 */
void
asyncio_send_unlock(async_fd_t *af)
{
  if(af->af_flags & AF_SENDQ_MUTEX)
    pthread_mutex_unlock(&af->af_sendq_mutex);
}


/**
 *
 */
int
asyncio_sendq_with_hdr_locked(async_fd_t *af, const void *hdr_buf,
                              size_t hdr_len, mbuf_t *q, int cork)
{
  int rval = 0;

  if(af->af_fd != -1) {
    int qempty = af->af_sendq.mq_size == 0;

    if(!cork && qempty) {
      int r = send(af->af_fd, hdr_buf, hdr_len, MSG_NOSIGNAL | MSG_MORE);
      if(r > 0) {
        hdr_buf += r;
        hdr_len -= r;
      }
    }

    if(hdr_len > 0) {
      mbuf_append(&af->af_sendq, hdr_buf, hdr_len);
      qempty = 0;
    }
    mbuf_appendq(&af->af_sendq, q);
    if(!cork)
      do_write(af);
  } else {
    mbuf_clear(q);
    rval = 1;
  }

  return rval;
}


/**
 *
 */
int
asyncio_sendq_with_hdr(async_fd_t *af, const void *hdr_buf, size_t hdr_len,
                       mbuf_t *q, int cork)
{
  if(af->af_flags & AF_SENDQ_MUTEX)
    pthread_mutex_lock(&af->af_sendq_mutex);

  int rval = asyncio_sendq_with_hdr_locked(af, hdr_buf, hdr_len, q, cork);
  if(af->af_flags & AF_SENDQ_MUTEX)
    pthread_mutex_unlock(&af->af_sendq_mutex);
  return rval;
}


/**
 *
 */
async_fd_t *
asyncio_bind(const char *bindaddr, int port,
             asyncio_accept_cb_t *cb,
             void *opaque)
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
  af->af_opaque = opaque;
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
  pthread_cond_init(&af->af_sendq_cond, NULL);

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
asyncio_enable_read(async_fd_t *af)
{
  assert(pthread_self() == asyncio_tid);

  if(af->af_flags & AF_SENDQ_MUTEX)
    pthread_mutex_lock(&af->af_sendq_mutex);

  mod_poll_flags(af, EPOLLIN, 0);

  if(af->af_flags & AF_SENDQ_MUTEX)
    pthread_mutex_unlock(&af->af_sendq_mutex);

  if(af->af_recvq.mq_size)
    af->af_bytes_avail(af->af_opaque, &af->af_recvq);
}


/**
 *
 */
void
asyncio_disable_read(async_fd_t *af)
{
  assert(pthread_self() == asyncio_tid);

  if(af->af_flags & AF_SENDQ_MUTEX)
    pthread_mutex_lock(&af->af_sendq_mutex);

  mod_poll_flags(af, 0, EPOLLIN);

  if(af->af_flags & AF_SENDQ_MUTEX)
    pthread_mutex_unlock(&af->af_sendq_mutex);
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
    asyncio_timer_arm_delta(&af->af_timer, retry * 1000);
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
  asyncio_timer_arm_delta(&af->af_timer, timeout * 1000);
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

  asyncio_timer_arm_delta(&af->af_timer, delay * 1000);
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
static void
task_cb(void)
{
  pthread_mutex_lock(&asyncio_task_mutex);
  while(1) {
    asyncio_task_t *at;
    at = TAILQ_FIRST(&asyncio_tasks);
    if(at != NULL)
      TAILQ_REMOVE(&asyncio_tasks, at, at_link);
    if(at == NULL)
      break;
    pthread_mutex_unlock(&asyncio_task_mutex);
    at->at_fn(at->at_aux);
    pthread_mutex_lock(&asyncio_task_mutex);
    if(at->at_block) {
      at->at_block = 0;
      pthread_cond_broadcast(&asyncio_task_cond);
    } else {
      free(at);
    }
  }
  pthread_mutex_unlock(&asyncio_task_mutex);
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
  fcntl(asyncio_pipe[0], F_SETFD, fcntl(asyncio_pipe[0], F_GETFD) | FD_CLOEXEC);
  fcntl(asyncio_pipe[1], F_SETFD, fcntl(asyncio_pipe[1], F_GETFD) | FD_CLOEXEC);

  TAILQ_INIT(&asyncio_dns_pending);
  TAILQ_INIT(&asyncio_dns_completed);
  TAILQ_INIT(&asyncio_tasks);

#ifdef __linux__
  epfd = epoll_create1(EPOLL_CLOEXEC);
#endif

#ifdef __APPLE__
  epfd = kqueue();
#endif

  pthread_mutex_init(&asyncio_worker_mutex, NULL);
  pthread_mutex_init(&asyncio_task_mutex, NULL);
  pthread_cond_init(&asyncio_task_cond, NULL);

  asyncio_dns_worker = asyncio_add_worker(adr_deliver_cb);
  asyncio_task_worker = asyncio_add_worker(task_cb);

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


/**
 *
 */
static void
asyncio_run_task0(void (*fn)(void *aux), void *aux, int block)
{
  asyncio_task_t *at = malloc(sizeof(asyncio_task_t));
  at->at_fn = fn;
  at->at_aux = aux;
  at->at_block = block;
  pthread_mutex_lock(&asyncio_task_mutex);
  TAILQ_INSERT_TAIL(&asyncio_tasks, at, at_link);
  pthread_mutex_unlock(&asyncio_task_mutex);
  asyncio_wakeup_worker(asyncio_task_worker);

  if(block) {

    pthread_mutex_lock(&asyncio_task_mutex);
    while(at->at_block)
      pthread_cond_wait(&asyncio_task_cond, &asyncio_task_mutex);
    pthread_mutex_unlock(&asyncio_task_mutex);
    free(at);
  }
}

/**
 *
 */
void
asyncio_run_task(void (*fn)(void *aux), void *aux)
{
   asyncio_run_task0(fn, aux, 0);
}

/**
 *
 */
void
asyncio_run_task_blocking(void (*fn)(void *aux), void *aux)
{
  asyncio_run_task0(fn, aux, 1);
}
