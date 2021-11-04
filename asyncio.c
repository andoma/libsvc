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

#if defined(WITH_OPENSSL)
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#endif

#include "queue.h"
#include "asyncio.h"
#include "trace.h"
#include "talloc.h"
#include "sock.h"
#include "misc.h"
#include "libsvc.h"
#include "strvec.h"

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

LIST_HEAD(asyncio_timer_list, asyncio_timer);
LIST_HEAD(asyncio_worker_list, asyncio_worker);

static LIST_HEAD(, asyncio_fd) deferred_processings;

#if defined(WITH_OPENSSL)
struct asyncio_sslctx_host {
  char *ash_hostname;
  SSL_CTX *ash_ctx;
  int ash_wildcard;
};
struct asyncio_sslctx {
  atomic_t refcount;
  unsigned int client;

  size_t num_hosts;
  struct asyncio_sslctx_host hosts[0];
};


static struct asyncio_sslctx *
sslctx_alloc(size_t num_hosts)
{
  assert(num_hosts > 0);

  asyncio_sslctx_t *as = calloc(1, sizeof(struct asyncio_sslctx) +
                                sizeof(struct asyncio_sslctx_host) * num_hosts);
  as->num_hosts = num_hosts;
  atomic_set(&as->refcount, 1);
  return as;
}


static asyncio_sslctx_t *
sslctx_retain(asyncio_sslctx_t *ctx)
{
  if(ctx)
    atomic_inc(&ctx->refcount);
  return ctx;
}

static void
sslctx_release(asyncio_sslctx_t *ctx)
{
  if(!ctx || atomic_dec(&ctx->refcount))
    return;
  for(size_t i = 0; i < ctx->num_hosts; i++) {
    SSL_CTX_free(ctx->hosts[i].ash_ctx);
    free(ctx->hosts[i].ash_hostname);
  }
  free(ctx);
}
#endif

/**
 *
 */
struct asyncio_fd {
  asyncio_poll_cb_t *af_pollerr;
  asyncio_error_cb_t *af_error;
  asyncio_accept_cb_t *af_accept;
  asyncio_poll_cb_t *af_pollin;
  asyncio_poll_cb_t *af_pollout;
  asyncio_read_cb_t *af_bytes_avail;
  asyncio_socket_trace_cb_t *af_trace;

  int (*af_locked_write)(struct asyncio_fd *af, int canwrite);

  void *af_opaque;

  mbuf_grp_t *af_sendq;
  mbuf_t af_recvq;

  char *af_hostname;

  pthread_mutex_t af_sendq_mutex;
  pthread_cond_t af_sendq_cond;

  atomic_t af_refcount;
  int af_fd;
  int af_epoll_flags;
  uint16_t af_port;

  uint16_t af_flags;

  uint8_t af_pending_shutdown;
  uint8_t af_deferred_processing;
  int af_pending_error;

  char *af_title;

#if defined(WITH_OPENSSL)
  int af_ssl_established;
  int af_ssl_read_status;
  int af_ssl_write_status;
  SSL *af_ssl;
  asyncio_sslctx_t *af_sslctx;

  uint8_t af_handshake_inspect_buf[32];
  size_t af_handshake_inspect_buf_used;

#endif
  LIST_ENTRY(asyncio_fd) af_deferred_processing_link;
};




#define TW_TIME_SHIFT  18
#define TW_SLOTS 65536
#define TW_SLOT_MASK (TW_SLOTS - 1)

static struct asyncio_timer_list timerwheel[TW_SLOTS];
static int                timerwheel_read_pos;

static int asyncio_pipe[2];
static asyncio_fd_t *pipe_af;
static int epfd = -1;

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


static void
af_lock(asyncio_fd_t *af)
{
  if(af->af_flags & ASYNCIO_FLAG_THREAD_SAFE)
    pthread_mutex_lock(&af->af_sendq_mutex);
}

static void
af_unlock(asyncio_fd_t *af)
{
  if(af->af_flags & ASYNCIO_FLAG_THREAD_SAFE)
    pthread_mutex_unlock(&af->af_sendq_mutex);
}



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
setup_tcp_socket(int fd, int no_delay)
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

  val = !!no_delay;
  setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &val, sizeof(val));

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
asyncio_timer_init(asyncio_timer_t *at, void (*fn)(void *opaque, int64_t now),
		   void *opaque)
{
  at->at_fn = fn;
  at->at_opaque = opaque;
  at->at_expire = 0;
}


/**
 *
 */
int64_t
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
mod_poll_flags(asyncio_fd_t *af, int set, int clr)
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

  assert(epfd != -1);
  int r = epoll_ctl(epfd, op, af->af_fd, &e);

  if(r) {
    fprintf(stderr, "epoll_ctl(%d, %d, %x) for %s -- %s\n",
	    op, af->af_fd, e.events, af->af_title ?: "<noname>",
            strerror(errno));
  }

  af->af_epoll_flags = f;
}
#endif

#ifdef __APPLE__

#define EPOLLIN  0x1
#define EPOLLOUT 0x2
#define MSG_MORE 0

/**
 *
 */
static void
mod_poll_flags(asyncio_fd_t *af, int set, int clr)
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
static asyncio_fd_t *
asyncio_fd_create(int fd, int initial_poll_flags)
{
  asyncio_fd_t *af = calloc(1, sizeof(asyncio_fd_t));
  af->af_fd = fd;
  atomic_set(&af->af_refcount, 1);
  af->af_sendq = mbuf_grp_create(MBUF_GRP_MODE_STRICT_PRIORITY);
  mbuf_init(&af->af_recvq);
  mod_poll_flags(af, initial_poll_flags, 0);
  return af;
}


/**
 *
 */
void
asyncio_fd_retain(asyncio_fd_t *af)
{
  atomic_inc(&af->af_refcount);
}


/**
 *
 */
void
asyncio_fd_release(asyncio_fd_t *af)
{
  if(atomic_dec(&af->af_refcount))
    return;

  assert(af->af_fd == -1);

  if(af->af_flags & ASYNCIO_FLAG_THREAD_SAFE) {
    pthread_mutex_destroy(&af->af_sendq_mutex);
    pthread_cond_destroy(&af->af_sendq_cond);
  }

  mbuf_grp_destroy(af->af_sendq);
  mbuf_clear(&af->af_recvq);
  free(af->af_hostname);
  free(af->af_title);

#if defined(WITH_OPENSSL)
  sslctx_release(af->af_sslctx);
#endif
  free(af);
}



/**
 *
 */
static int
do_write_locked(asyncio_fd_t *af, int can_write)
{
  while(1) {
    const void *buf;

    size_t avail = mbuf_grp_peek_no_copy(af->af_sendq, &buf);
    if(avail == 0) {
      if(af->af_pending_shutdown) {
        shutdown(af->af_fd, 2);
      }
      // Nothing more to send
      mod_poll_flags(af, 0, EPOLLOUT);
      return 0;
    }

    int r = send(af->af_fd, buf, avail, MSG_NOSIGNAL);
    if(r == 0)
      break;

    if(r == -1 && (errno == EAGAIN || errno == EINTR))
      break;

    if(r == -1) {
      mod_poll_flags(af, 0, EPOLLOUT);
      return errno;
    }
    assert(r <= avail);
    mbuf_grp_drop(af->af_sendq, r);

    if(af->af_flags & ASYNCIO_FLAG_THREAD_SAFE)
      pthread_cond_signal(&af->af_sendq_cond);

    if(r != avail)
      break;
  }

  mod_poll_flags(af, EPOLLOUT, 0);
  return 0;
}



/**
 *
 */
int
asyncio_wait_send_buffer(asyncio_fd_t *af, int size)
{
  int r = 0;
  pthread_mutex_lock(&af->af_sendq_mutex);

  while(1) {
    if(af->af_pending_error) {
      r = af->af_pending_error;
      break;
    }

    if(size > mbuf_grp_size(af->af_sendq))
      break;

    pthread_cond_wait(&af->af_sendq_cond, &af->af_sendq_mutex);
  }
  pthread_mutex_unlock(&af->af_sendq_mutex);
  return r;
}


/**
 *
 */
size_t
asyncio_fd_get_queue_length(asyncio_fd_t *af, int queue_index)
{
  af_lock(af);
  size_t r = mbuf_grp_size_for_queue(af->af_sendq, queue_index);
  af_unlock(af);
  return r;
}


int
asyncio_get_fd(asyncio_fd_t *af)
{
  return af->af_fd;
}


/**
 *
 */
static void
do_error(asyncio_fd_t *af, int error)
{
  if(af->af_flags & ASYNCIO_FLAG_THREAD_SAFE) {
    pthread_mutex_lock(&af->af_sendq_mutex);
    af->af_pending_error = error ?: -1;
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
do_write_pollout(asyncio_fd_t *af)
{
  af_lock(af);
  int err = af->af_fd == -1 ? 0 : af->af_locked_write(af, 1);
  af_unlock(af);
  if(err)
    do_error(af, err);
}


/**
 *
 */
static void
do_read(asyncio_fd_t *af)
{
  char tmp[1024];
  while(1) {
    int r = read(af->af_fd, tmp, sizeof(tmp));
    if(r == 0) {
      if(af->af_recvq.mq_size)
        af->af_bytes_avail(af->af_opaque, &af->af_recvq);
      do_error(af, 0);
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



#if defined(WITH_OPENSSL)
static void __attribute__((unused))
ssldump(asyncio_fd_t *af)
{
  unsigned long e;
  char errbuf[512];
  while((e = ERR_get_error()) != 0) {
    ERR_error_string_n(e, errbuf, sizeof(errbuf));
    trace(LOG_INFO, "SSL: %s: %s", af->af_title, errbuf);
  }
}



/**
 *
 */
static int
verify_hostname(const char *hostname, X509 *cert, char *errbuf, size_t errlen)
{
  int i;
  /* domainname is the "domain" we wan't to access (actually hostname
   * with first part of the DNS name removed) */
  const char *domainname = strchr(hostname, '.');
  if(domainname != NULL) {
      domainname++;
      if(strlen(domainname) == 0)
        domainname = NULL;
  }


  // First check commonName

  X509_NAME *subjectName;
  char commonName[256];

  subjectName = X509_get_subject_name(cert);
  if(X509_NAME_get_text_by_NID(subjectName, NID_commonName,
                               commonName, sizeof(commonName)) != -1) {
    if(!strcmp(commonName, hostname))
      return 0;
  }

  // Then check altNames

  GENERAL_NAMES *names = X509_get_ext_d2i( cert, NID_subject_alt_name, 0, 0);
  if(names == NULL) {
    snprintf(errbuf, errlen, "SSL: No subjectAltName extension");
    return -1;
  }

  const int num_names = sk_GENERAL_NAME_num(names);

  for(i = 0; i < num_names; ++i ) {
    GENERAL_NAME *name = sk_GENERAL_NAME_value(names, i);
    unsigned char *dns;
    int match;

    if(name->type != GEN_DNS)
      continue;

    ASN1_STRING_to_UTF8(&dns, name->d.dNSName);
    if(dns[0] == '*' && dns[1] == '.') {
      match = domainname != NULL && !strcasecmp((char *)dns+2, domainname);
    } else {
      match = !strcasecmp((char *)dns, hostname);
    }

    OPENSSL_free(dns);
    if(match) {
      GENERAL_NAMES_free(names);
      return 0;
    }
  }
  GENERAL_NAMES_free(names);
  snprintf(errbuf, errlen, "SSL: Hostname mismatch");
  return -1;
}


static int
asyncio_ssl_verify(asyncio_fd_t *af)
{
  X509 *peer = SSL_get_peer_certificate(af->af_ssl);
  if(peer == NULL) {
    if(af->af_trace)
      af->af_trace(af->af_opaque, "No peer certificate");
    return EDOM;
  }

  const int err = SSL_get_verify_result(af->af_ssl);
  if(err != X509_V_OK) {
    if(af->af_trace)
      af->af_trace(af->af_opaque, "Certificate does not verify");
    X509_free(peer);
    return EDOM;
  }

  char errbuf[512];
  if(verify_hostname(af->af_hostname, peer, errbuf, sizeof(errbuf))) {
    X509_free(peer);
    if(af->af_trace) {
      scoped_char *err = fmt("Mismatching hostname: %s", errbuf);
      af->af_trace(af->af_opaque, err);
    }
    return EDOM;
  }
  X509_free(peer);
  return 0;
}


/**
 *
 */
static char *
ssl_poll_errstack()
{
  scoped_strvec(errors);

  unsigned long e;
  char errbuf[512];
  while((e = ERR_get_error()) != 0) {
    ERR_error_string_n(e, errbuf, sizeof(errbuf));
    strvec_push(&errors, errbuf);
  }
  return strvec_join(&errors, ", ");
}



/**
 *
 */
static int
asyncio_ssl_handshake(asyncio_fd_t *af)
{
  if(af->af_trace && af->af_handshake_inspect_buf_used == 0) {

    int x = recv(af->af_fd, af->af_handshake_inspect_buf,
                 sizeof(af->af_handshake_inspect_buf), MSG_PEEK);
    if(x > 0) {
      af->af_handshake_inspect_buf_used = x;
    }
  }

  int r = SSL_do_handshake(af->af_ssl);
  int err = SSL_get_error(af->af_ssl, r);
  switch(err) {
  case SSL_ERROR_WANT_READ:
    mod_poll_flags(af, EPOLLIN, EPOLLOUT);
    return 0;

  case SSL_ERROR_WANT_WRITE:
    mod_poll_flags(af, EPOLLOUT, EPOLLIN);
    return 0;

  case SSL_ERROR_NONE:
    mod_poll_flags(af, EPOLLIN, EPOLLOUT);
    if(mbuf_grp_size(af->af_sendq))
      mod_poll_flags(af, EPOLLOUT, 0);

    af->af_ssl_established = 1;

    if(af->af_trace)
      af->af_trace(af->af_opaque, "TLS established");

    if(af->af_hostname != NULL &&
       af->af_flags & ASYNCIO_FLAG_SSL_VERIFY_CERT)
      return asyncio_ssl_verify(af);

    return 0;
  }

  scoped_char *sslerr = ssl_poll_errstack();

  if(af->af_trace) {
    char hex[sizeof(af->af_handshake_inspect_buf) * 3 + 1];
    char *dst = hex;
    size_t i;
    for(i = 0; i < af->af_handshake_inspect_buf_used; i++) {
      if(i)
        *dst++ = ' ';
      uint8_t v = af->af_handshake_inspect_buf[i];
      *dst++ = "0123456789abcdef"[v >> 4];
      *dst++ = "0123456789abcdef"[v & 15];
      }
    *dst = 0;

    scoped_char *msg = fmt("SSL Handshake failed err:%d r:%d sslerr:%s recv:[%s]",
                           err, r, sslerr, hex);
    af->af_trace(af->af_opaque, msg);
  }
  return ENOLINK;
}




static void
do_ssl_update_poll_flags_ex(asyncio_fd_t *af, int line)
{
#if 0
  printf("Update poll flags line %d\n", line);
  printf("  READ: %s\n",
         af->af_ssl_read_status == SSL_ERROR_WANT_READ  ? "READ" :
         af->af_ssl_read_status == SSL_ERROR_WANT_WRITE ? "WRITE" : "-");

  printf(" WRITE: %s\n",
         af->af_ssl_write_status == SSL_ERROR_WANT_READ  ? "READ" :
         af->af_ssl_write_status == SSL_ERROR_WANT_WRITE ? "WRITE" : "-");
#endif
  int events = 0;
  if(af->af_ssl_read_status == SSL_ERROR_WANT_WRITE) {
    events |= EPOLLOUT;
  } else {
    events |= EPOLLIN;
  }

  if(af->af_ssl_write_status == SSL_ERROR_WANT_WRITE) {
    events |= EPOLLOUT;
  } else if(af->af_ssl_write_status == SSL_ERROR_WANT_READ) {
    events |= EPOLLIN;
  }
  //  printf("mod poll flags: %x\n", events);
  mod_poll_flags(af, events, ~events & (EPOLLIN | EPOLLOUT));
}


#define do_ssl_update_poll_flags(af) \
  do_ssl_update_poll_flags_ex(af, __LINE__)

static int do_ssl_write_locked(asyncio_fd_t *af, int canwrite);


/**
 *
 */
static int
do_ssl_read_locked(asyncio_fd_t *af)
{
  char buf[4096];
  af->af_ssl_read_status = 0;

  for(int i = 0; i < 10 && af->af_ssl != NULL; i++) {
    if(af->af_ssl_write_status == SSL_ERROR_WANT_READ) {
      return 0;
    }
    af->af_ssl_read_status = 0;
    int r = SSL_read(af->af_ssl, buf, sizeof(buf));
    int err = SSL_get_error(af->af_ssl, r);
    switch(err) {
    case SSL_ERROR_NONE:
      mbuf_append(&af->af_recvq, buf, r);
      break;

    case SSL_ERROR_ZERO_RETURN:
      // Conection closed
      do_ssl_update_poll_flags(af);
      return ECONNRESET;

    case SSL_ERROR_SYSCALL:
      return errno ?: ECONNRESET;

    default:
      do_ssl_update_poll_flags(af);

      {
        scoped_char *sslerr = ssl_poll_errstack();

        if(af->af_trace) {
          scoped_char *msg = fmt("SSL Error err:%d r:%d sslerr:%s", err, r, sslerr);
          af->af_trace(af->af_opaque, msg);
        }
      }
      return ENOLINK;

    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE:
      af->af_ssl_read_status = err;
      do_ssl_update_poll_flags(af);
      return 0;
    }

    af_unlock(af);
    af->af_bytes_avail(af->af_opaque, &af->af_recvq);
    af_lock(af);
  }
  return 0;
}

/**
 *
 */
static void
do_ssl_read(asyncio_fd_t *af)
{
  af_lock(af);

  if(!af->af_ssl_established) {
    int err = asyncio_ssl_handshake(af);
    af_unlock(af);
    if(err)
      do_error(af, err);
    return;
  }

  if(af->af_ssl_write_status == SSL_ERROR_WANT_READ) {
    do_ssl_write_locked(af, 1);
    af_unlock(af);
    return;
  }

  af->af_ssl_read_status = 0;

  int err = do_ssl_read_locked(af);

  af_unlock(af);
  if(err)
    do_error(af, err);
}


static int
do_ssl_write_locked(asyncio_fd_t *af, int canwrite)
{
  if(!af->af_ssl_established) {
    return asyncio_ssl_handshake(af);
  }

  if(af->af_ssl_read_status == SSL_ERROR_WANT_WRITE) {
    do_ssl_read_locked(af);
    return 0;
  }

  if(!canwrite && af->af_ssl_write_status) {
    return 0; // Just trying to write and we're still haven't got POLLOUT
  }
  while(1) {
    af->af_ssl_write_status = 0;
    const void *buf;
    const size_t avail = mbuf_grp_peek_no_copy(af->af_sendq, &buf);
    if(avail == 0) {
      if(af->af_pending_shutdown) {
        SSL_shutdown(af->af_ssl);
      }
      do_ssl_update_poll_flags(af);
      return 0;
    }

    const int r = SSL_write(af->af_ssl, buf, avail);
    const int err = SSL_get_error(af->af_ssl, r);
    switch(err) {
    case SSL_ERROR_NONE:
      mbuf_grp_drop(af->af_sendq, r);
      if(af->af_flags & ASYNCIO_FLAG_THREAD_SAFE)
        pthread_cond_signal(&af->af_sendq_cond);
      continue;

    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE:
      af->af_ssl_write_status = err;
      do_ssl_update_poll_flags(af);
      return 0;

    default:
      do_ssl_update_poll_flags(af);

      {
        scoped_char *sslerr = ssl_poll_errstack();

        if(af->af_trace) {
          scoped_char *msg = fmt("SSL Error err:%d r:%d sslerr:%s", err, r, sslerr);
          af->af_trace(af->af_opaque, msg);
        }
      }
      return 0;
    }
  }
}
#endif


/**
 *
 */
static void
do_accept(asyncio_fd_t *af)
{
  struct sockaddr_storage remote, local;
  socklen_t slen;

  slen = sizeof(struct sockaddr_storage);

  int fd = libsvc_accept(af->af_fd, (struct sockaddr *)&remote, &slen);
  if(fd == -1) {
    perror("accept");
    return;
  }

  setup_tcp_socket(fd, af->af_flags & ASYNCIO_FLAG_NO_DELAY);

  slen = sizeof(struct sockaddr_storage);
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
      at->at_fn(at->at_opaque, now);
      cbs++;
    }
  }

  const int slottime = 1 << TW_TIME_SHIFT;
  int spill = now & (slottime - 1);
  return (slottime - spill) / 1000 + 1;
}



static void
process_deferred(void)
{
  asyncio_fd_t *af;

  while((af = LIST_FIRST(&deferred_processings)) != NULL) {
    LIST_REMOVE(af, af_deferred_processing_link);
    af->af_deferred_processing = 0;
    if(af->af_recvq.mq_size)
      af->af_bytes_avail(af->af_opaque, &af->af_recvq);
  }
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

    process_deferred();

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
      asyncio_fd_t *af = ev[i].data.ptr;
      atomic_inc(&af->af_refcount);
    }

    for(i = 0; i < r; i++) {
      asyncio_fd_t *af = ev[i].data.ptr;
      if(af->af_fd == -1)
        continue;

      if(ev[i].events & EPOLLIN) {
	af->af_pollin(af);
      }

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

    }
    for(i = 0; i < r; i++) {
      asyncio_fd_t *af = ev[i].data.ptr;
      asyncio_fd_release(af);
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
      asyncio_fd_t *af = events[i].udata;
      atomic_inc(&af->af_refcount);
    }

    for(i = 0; i < r; i++) {
      asyncio_fd_t *af = events[i].udata;
      if(events[i].filter == EVFILT_READ) {
        af->af_pollin(af);

        if(events[i].flags & EV_EOF) {
          do_error(af, ECONNRESET);
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
      asyncio_fd_t *af = events[i].udata;
      asyncio_fd_release(af);
    }

#endif
  }
  return NULL;
}


/**
 *
 */
void
asyncio_close(asyncio_fd_t *af)
{
  assert(pthread_self() == asyncio_tid);

  if(af->af_deferred_processing) {
    af->af_deferred_processing = 0;
    LIST_REMOVE(af, af_deferred_processing_link);
  }

  af_lock(af);

#if defined(WITH_OPENSSL)
  if(af->af_ssl != NULL) {
    SSL_free(af->af_ssl);
    af->af_ssl = NULL;
  }
#endif

  if(af->af_fd != -1) {
    mod_poll_flags(af, 0, -1);
    close(af->af_fd);
    af->af_fd = -1;
  }

  if(af->af_flags & ASYNCIO_FLAG_THREAD_SAFE)
    pthread_mutex_unlock(&af->af_sendq_mutex);
  else
    asyncio_fd_release(af);
}


/**
 *
 */
void
asyncio_shutdown(asyncio_fd_t *af)
{
  af_lock(af);

  if(af->af_fd != -1) {
    if(mbuf_grp_size(af->af_sendq)) {
      af->af_pending_shutdown = 1;
#if defined(WITH_OPENSSL)
    } else if(af->af_ssl != NULL) {
      SSL_shutdown(af->af_ssl);
#endif
    } else {
      shutdown(af->af_fd, 2);
    }
  }
  af_unlock(af);
}

/**
 *
 */
static int
send_locked_write(asyncio_fd_t *af)
{
  const int err = af->af_locked_write(af, 0);
  if(err) {
    return -1;
  }
  return 0;
}


/**
 *
 */
int
asyncio_send(asyncio_fd_t *af, const void *buf, size_t len, int cork)
{
  int rval = 0;
  af_lock(af);

  if(af->af_fd != -1) {
    mbuf_grp_append(af->af_sendq, 0, buf, len, 0);

    if(!cork)
      rval = send_locked_write(af);
  } else {
    rval = -1;
  }

  af_unlock(af);
  return rval;
}


/**
 *
 */
int
asyncio_send_with_hdr(asyncio_fd_t *af,
                      const void *hdr_buf, size_t hdr_len,
                      const void *buf, size_t len,
                      int cork, int queue_index)
{
  int start_of_message = 1;
  int rval = 0;
  af_lock(af);

#if defined(WITH_OPENSSL)
  const int no_ssl = af->af_ssl == NULL;
#else
  const int no_ssl = 1;
#endif

  if(af->af_fd != -1) {
    int qempty = mbuf_grp_size(af->af_sendq) == 0;

    if(!cork && qempty && no_ssl && hdr_len) {
      int r = send(af->af_fd, hdr_buf, hdr_len, MSG_NOSIGNAL | MSG_MORE);
      if(r > 0) {
        hdr_buf += r;
        hdr_len -= r;
        start_of_message = 0;
      }
    }

    if(hdr_len > 0) {
      mbuf_grp_append(af->af_sendq, queue_index,
                      hdr_buf, hdr_len, start_of_message);
      start_of_message = 0;
      qempty = 0;
    }

    if(!cork && qempty && no_ssl) {
      int r = send(af->af_fd, buf, len, MSG_NOSIGNAL);
      if(r > 0) {
        buf += r;
        len -= r;
      }
    }

    if(len > 0) {
      mbuf_grp_append(af->af_sendq, queue_index, buf, len, start_of_message);
      qempty = 0;
    }

    if(!cork)
      rval = send_locked_write(af);
  } else {
    rval = -1;
  }

  af_unlock(af);
  return rval;
}


/**
 *
 */
int
asyncio_sendq(asyncio_fd_t *af, mbuf_t *q, int cork, int queue_index)
{
  int rval = 0;
  af_lock(af);

  if(af->af_fd != -1) {
    mbuf_grp_appendq(af->af_sendq, queue_index, q);
    if(!cork)
      rval = send_locked_write(af);
  } else {
    mbuf_clear(q);
    rval = 1;
  }
  af_unlock(af);
  return rval;
}


/**
 *
 */
void
asyncio_send_lock(asyncio_fd_t *af)
{
  af_lock(af);
}


/**
 *
 */
void
asyncio_send_unlock(asyncio_fd_t *af)
{
  af_unlock(af);
}


/**
 *
 */
int
asyncio_sendq_with_hdr_locked(asyncio_fd_t *af, const void *hdr_buf,
                              size_t hdr_len, mbuf_t *q, int cork,
                              int queue_index)
{
  int rval = 0;
  int start_of_message = 1;
#if defined(WITH_OPENSSL)
  const int no_ssl = af->af_ssl == NULL;
#else
  const int no_ssl = 1;
#endif

  if(af->af_fd != -1) {
    int qempty = mbuf_grp_size(af->af_sendq)== 0;

    if(!cork && qempty && no_ssl) {
      int r = send(af->af_fd, hdr_buf, hdr_len, MSG_NOSIGNAL | MSG_MORE);
      if(r > 0) {
        hdr_buf += r;
        hdr_len -= r;
        start_of_message = 0;
      }
    }

    if(hdr_len > 0) {
      mbuf_grp_append(af->af_sendq, queue_index,
                      hdr_buf, hdr_len, start_of_message);
      qempty = 0;
    }
    mbuf_grp_appendq(af->af_sendq, queue_index, q);
    if(!cork)
      rval = send_locked_write(af);
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
asyncio_sendq_with_hdr(asyncio_fd_t *af, const void *hdr_buf, size_t hdr_len,
                       mbuf_t *q, int cork, int queue_index)
{
  if(af->af_flags & ASYNCIO_FLAG_THREAD_SAFE)
    pthread_mutex_lock(&af->af_sendq_mutex);

  int rval = asyncio_sendq_with_hdr_locked(af, hdr_buf, hdr_len, q, cork,
                                           queue_index);
  if(af->af_flags & ASYNCIO_FLAG_THREAD_SAFE)
    pthread_mutex_unlock(&af->af_sendq_mutex);
  return rval;
}


/**
 *
 */
asyncio_fd_t *
asyncio_bind(const char *bindaddr, int port,
             asyncio_accept_cb_t *cb,
             void *opaque, int flags)
{
  int fd, ret;
  int one = 1;

  fd = libsvc_socket(bindaddr == NULL ? AF_INET6 : AF_INET, SOCK_STREAM, 0);
  if(fd == -1)
    return NULL;

  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(int));

  setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(int));

  setup_tcp_socket(fd, 0);

  if(bindaddr == NULL) {
    struct sockaddr_in6 la = {
      .sin6_family = AF_INET6,
      .sin6_port = htons(port)
    };

    ret = bind(fd, (struct sockaddr *)&la, sizeof(la));
    if(ret < 0) {
      int x = errno;
      trace(LOG_ERR, "Unable to bind 0.0.0.0:%d -- %s",
            port, strerror(errno));
      close(fd);
      errno = x;
      return NULL;
    }

    int off = 0;
    setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof(int));

  } else {
    struct sockaddr_in la = {
      .sin_family = AF_INET,
      .sin_port = htons(port),
      .sin_addr.s_addr = inet_addr(bindaddr)
    };
    ret = bind(fd, (struct sockaddr *)&la, sizeof(la));
    if(ret < 0) {
      int x = errno;
      trace(LOG_ERR, "Unable to bind %s:%d -- %s",
            bindaddr, port, strerror(errno));
      close(fd);
      errno = x;
      return NULL;
    }
  }

  listen(fd, 100);

  asyncio_fd_t *af = asyncio_fd_create(fd, EPOLLIN);
  af->af_flags = flags;
  af->af_pollin = &do_accept;
  af->af_accept = cb;
  af->af_opaque = opaque;
  return af;
}


/**
 *
 */
asyncio_fd_t *
asyncio_dgram(int fd,
              asyncio_poll_cb_t *input,
              void *opaque)
{
  set_nonblocking(fd, 1);
  asyncio_fd_t *af = asyncio_fd_create(fd, EPOLLIN);
  af->af_pollin  = input;
  af->af_opaque = opaque;
  return af;
}


static void
asyncio_connect_pollout(struct asyncio_fd *af)
{
  int err;
  socklen_t sockerrlen = sizeof(err);
  getsockopt(af->af_fd, SOL_SOCKET, SO_ERROR, (void *)&err, &sockerrlen);
  af->af_error(af->af_opaque, err);
}

/**
 *
 */
asyncio_fd_t *
asyncio_connect(int fd, asyncio_error_cb_t *cb, void *opaque)
{
  set_nonblocking(fd, 1);
  asyncio_fd_t *af = asyncio_fd_create(fd, EPOLLOUT);
  af->af_pollout = asyncio_connect_pollout;
  af->af_error = cb;
  af->af_opaque = opaque;
  return af;
}


int
asyncio_detach(asyncio_fd_t *af)
{
  int fd = af->af_fd;
  mod_poll_flags(af, 0, -1);
  af->af_fd = -1;
  return fd;
}




/**
 *
 */
asyncio_fd_t *
asyncio_stream(int fd,
               asyncio_read_cb_t *read,
               asyncio_error_cb_t *err,
               void *opaque,
               int flags,
               asyncio_sslctx_t *sslctx,
               const char *hostname,
               const char *title,
               asyncio_socket_trace_cb_t *tracecb)
{
  int poll_flags = EPOLLIN;
  setup_tcp_socket(fd, flags & ASYNCIO_FLAG_NO_DELAY);
  asyncio_fd_t *af = asyncio_fd_create(fd, 0);

  af->af_flags = flags;
  af->af_hostname = hostname ? strdup(hostname) : NULL;
  af->af_trace = tracecb;

  if(flags & ASYNCIO_FLAG_THREAD_SAFE) {
    pthread_mutex_init(&af->af_sendq_mutex, NULL);
    pthread_cond_init(&af->af_sendq_cond, NULL);
  }

  af->af_title = strdup(title);

  if(sslctx != NULL) {
#if defined(WITH_OPENSSL)

    af->af_sslctx = sslctx_retain(sslctx);

    af->af_ssl = SSL_new(sslctx->hosts[0].ash_ctx);
    if(SSL_set_fd(af->af_ssl, fd) == 0) {
      trace(LOG_ERR, "SSL: Unable to set FD");
    }

    if(hostname != NULL)
      SSL_set_tlsext_host_name(af->af_ssl, hostname);

    SSL_set_mode(af->af_ssl,
                 SSL_MODE_ENABLE_PARTIAL_WRITE |
                 SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

    if(sslctx->client) {
      SSL_set_connect_state(af->af_ssl);
      poll_flags = EPOLLOUT;
    } else {
      SSL_set_accept_state(af->af_ssl);
    }

    af->af_pollin  = &do_ssl_read;
    af->af_locked_write = &do_ssl_write_locked;
#else
    trace(LOG_ERR, "SSL not enabled");
    return NULL;
#endif
  } else {
    af->af_pollin  = &do_read;
    af->af_locked_write = &do_write_locked;
  }

  af->af_pollout = &do_write_pollout;

  af->af_bytes_avail = read;
  af->af_error = err;
  af->af_opaque = opaque;
  mod_poll_flags(af, poll_flags, 0);
  return af;
}


/**
 *
 */
void
asyncio_process_pending(asyncio_fd_t *af)
{
  assert(pthread_self() == asyncio_tid);

  if(!af->af_deferred_processing) {
    af->af_deferred_processing = 1;
    LIST_INSERT_HEAD(&deferred_processings, af, af_deferred_processing_link);
  }
}


/**
 *
 */
static void
asyncio_handle_pipe(asyncio_fd_t *af)
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


static void __attribute__((constructor))
asyncio_early_init(void)
{
#ifdef __linux__
  epfd = epoll_create1(EPOLL_CLOEXEC);
#endif

#ifdef __APPLE__
  epfd = kqueue();
#endif
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

  TAILQ_INIT(&asyncio_tasks);

  pthread_mutex_init(&asyncio_worker_mutex, NULL);
  pthread_mutex_init(&asyncio_task_mutex, NULL);
  pthread_cond_init(&asyncio_task_cond, NULL);

  asyncio_task_worker = asyncio_add_worker(task_cb);

  pipe_af = asyncio_fd_create(asyncio_pipe[0], EPOLLIN);
  pipe_af->af_pollin = &asyncio_handle_pipe;

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

/************************************************************************
 * SSL / TLS
 ************************************************************************/

#if defined(WITH_OPENSSL)


const char *
asyncio_fd_get_sni_name(asyncio_fd_t *af)
{
  if(af->af_ssl == NULL)
    return NULL;
  return SSL_get_servername(af->af_ssl, TLSEXT_NAMETYPE_host_name);
}


static EVP_PKEY *
evp_from_private_pem(const char *pem)
{
  if(pem == NULL)
    return NULL;

  size_t pemlen = strlen(pem);
  BIO *bio = BIO_new_mem_buf((void *)pem, pemlen);
  EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
  BIO_free(bio);
  return pkey;
}


static SSL_CTX *
ssl_ctx_from_pem(const char *priv_key_pem, const char *cert_pem)
{
  EVP_PKEY *priv_key = evp_from_private_pem(priv_key_pem);
  if(priv_key == NULL)
    return NULL;

  SSL_CTX *ctx = SSL_CTX_new(SSLv23_server_method());

  SSL_CTX_use_PrivateKey(ctx, priv_key);
  EVP_PKEY_free(priv_key);

  if(cert_pem != NULL) {
    BIO *bio = BIO_new_mem_buf((void *)cert_pem, strlen(cert_pem));

    X509 *cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    if(cert == NULL) {
      SSL_CTX_free(ctx);
      BIO_free(bio);
      trace(LOG_ERR, "Unable to load certificate");
      return NULL;
    }

    SSL_CTX_use_certificate(ctx, cert);
    X509_free(cert);
    X509 *ca;

    while((ca = PEM_read_bio_X509(bio, NULL, NULL, NULL)) != NULL) {
      if(!SSL_CTX_add0_chain_cert(ctx, ca)) {
        trace(LOG_ERR, "Unable to add CA certificate chain");
        X509_free(ca);
        SSL_CTX_free(ctx);
        BIO_free(bio);
        return NULL;
      }
    }

    BIO_free(bio);
  }

  SSL_CTX_set_cipher_list(ctx, getenv("LIBSVC_CIPHERLIST") ?: "HIGH");

  int r = SSL_CTX_check_private_key(ctx);
  if(r != 1) {
    trace(LOG_ERR, "Certificate/private key file mismatch");
    SSL_CTX_free(ctx);
    return NULL;
  }

  SSL_CTX_set_options(ctx,
                      SSL_OP_NO_SSLv2 |
                      SSL_OP_NO_SSLv3 |
                      SSL_OP_NO_TLSv1 |
                      SSL_OP_NO_TLSv1_1);
  return ctx;
}


asyncio_sslctx_t *
asyncio_sslctx_server_from_pem(const char *priv_key_pem,
                               const char *cert_pem)
{
  SSL_CTX *ctx = ssl_ctx_from_pem(priv_key_pem, cert_pem);
  if(ctx == NULL)
    return NULL;

  asyncio_sslctx_t *as = sslctx_alloc(1);
  as->hosts[0].ash_ctx = ctx;
  return as;
}

asyncio_sslctx_t *
asyncio_sslctx_server_from_files(const char *priv_key_file,
                                 const char *cert_file)
{

  char *cert_pem = readfile(cert_file, NULL);
  if(cert_pem == NULL) {
    trace(LOG_ERR, "Unable to load certificate file %s", cert_file);
    return NULL;
  }

  char *priv_key_pem = readfile(priv_key_file, NULL);
  if(priv_key_pem == NULL) {
    free(cert_pem);
    trace(LOG_ERR, "Unable to load private key file %s", priv_key_file);
    return NULL;
  }

  asyncio_sslctx_t *ctx =
    asyncio_sslctx_server_from_pem(priv_key_pem, cert_pem);
  memset(priv_key_pem, 0, strlen(priv_key_pem));
  free(priv_key_pem);
  free(cert_pem);
  return ctx;
}



static int
ash_match(struct asyncio_sslctx_host *ash, const char *hostname)
{
  if(ash->ash_hostname == NULL)
    return 0;

  if(!strcmp(ash->ash_hostname, hostname))
    return 1;

  if(!ash->ash_wildcard)
    return 0;

  const char *dot = strchr(hostname, '.');
  if(dot == NULL)
    return 0;
  return !strcmp(ash->ash_hostname, dot + 1);
}





static int
select_vhost_cb(SSL *s, int *ad, void *arg)
{
  const char *servername = SSL_get_servername(s, TLSEXT_NAMETYPE_host_name);
  asyncio_sslctx_t *as = arg;

  if(servername != NULL) {
    for(size_t i = 0; i < as->num_hosts; i++) {
      if(ash_match(&as->hosts[i], servername)) {
        SSL_set_SSL_CTX(s, as->hosts[i].ash_ctx);
        return SSL_TLSEXT_ERR_OK;
      }
    }
  }

  // Nothing found, select default if one is available
  for(size_t i = 0; i < as->num_hosts; i++) {
    if(as->hosts[i].ash_hostname == NULL) {
      SSL_set_SSL_CTX(s, as->hosts[i].ash_ctx);
      return SSL_TLSEXT_ERR_OK;
    }
  }

  return SSL_TLSEXT_ERR_ALERT_FATAL;
}


asyncio_sslctx_t *
asyncio_sslctx_server_hosts(const asyncio_sslhost_t *hosts, size_t num_hosts)
{
  if(num_hosts == 0)
    return NULL;

  asyncio_sslctx_t *as = sslctx_alloc(num_hosts);
  for(size_t i = 0; i < num_hosts; i++) {

    SSL_CTX *ctx = ssl_ctx_from_pem(hosts[i].priv_key_pem, hosts[i].cert_pem);
    if(ctx == NULL) {
      sslctx_release(as);
      return NULL;
    }
    as->hosts[i].ash_ctx = ctx;
    as->hosts[i].ash_hostname =
      hosts[i].hostname ? strdup(hosts[i].hostname) :NULL;
    as->hosts[i].ash_wildcard = hosts[i].is_wildcard;

    if(i == 0) {
      SSL_CTX_set_tlsext_servername_arg(ctx, as);
      SSL_CTX_set_tlsext_servername_callback(ctx, select_vhost_cb);
    }
  }
  return as;
}






asyncio_sslctx_t *
asyncio_sslctx_client(void)
{
  libsvc_openssl_init();

  SSL_CTX *ctx = SSL_CTX_new(TLSv1_2_client_method());

#if defined(__APPLE__)

#if defined(__aarch64__)

#if OPENSSL_VERSION_NUMBER >= 0x10100000
  const char *path = "/opt/homebrew/etc/openssl@1.1/cert.pem";
#else
  const char *path = "/opt/homebrew/etc/openssl/cert.pem";
#endif

#else

#if OPENSSL_VERSION_NUMBER >= 0x10100000
  const char *path = "/usr/local/etc/openssl@1.1/cert.pem";
#else
  const char *path = "/usr/local/etc/openssl/cert.pem";
#endif

#endif
  int r = SSL_CTX_load_verify_locations(ctx, path, NULL);
#else
  int r = SSL_CTX_load_verify_locations(ctx, NULL, "/etc/ssl/certs");
#endif
  if(!r) {
    SSL_CTX_free(ctx);
    return NULL;
  }

  SSL_CTX_set_verify_depth(ctx, 3);

  asyncio_sslctx_t *as = sslctx_alloc(1);
  as->client = 1;
  as->hosts[0].ash_ctx = ctx;
  return as;
}

void
asyncio_sslctx_free(asyncio_sslctx_t *ctx)
{
  sslctx_release(ctx);
}

#else

asyncio_sslctx_t *
asyncio_sslctx_client(void)
{
  return NULL;
}

asyncio_sslctx_t *
asyncio_sslctx_server_from_files(const char *priv_key_file,
                                 const char *cert_file)
{
  return NULL;
}


void
asyncio_sslctx_free(asyncio_sslctx_t *ctx)
{
}

#endif

