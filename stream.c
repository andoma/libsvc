#include <string.h>
#include <sys/param.h>

#include <errno.h>
#include <pthread.h>
#include <stdlib.h>

#include "stream.h"
#include "dial.h"
#include "asyncio.h"
#include "atomic.h"
#include "trace.h"
#include "misc.h"

struct stream {
  asyncio_fd_t *s_af;
  atomic_t s_refcount;
  int s_eos;
  int s_error;
  mbuf_t s_recv_buf;
  pthread_mutex_t s_recv_mutex;
  pthread_cond_t s_recv_cond;
};


static void
stream_release(stream_t *s)
{
  if(atomic_dec(&s->s_refcount))
    return;

  asyncio_fd_release(s->s_af);
  mbuf_clear(&s->s_recv_buf);
  pthread_mutex_destroy(&s->s_recv_mutex);
  pthread_cond_destroy(&s->s_recv_cond);
  free(s);
}


static void
stream_error(void *opaque, int error)
{
  stream_t *s = opaque;
  pthread_mutex_lock(&s->s_recv_mutex);
  s->s_eos = 1;
  s->s_error = error;
  pthread_cond_signal(&s->s_recv_cond);
  pthread_mutex_unlock(&s->s_recv_mutex);
  asyncio_close(s->s_af);
  stream_release(s);
}


static void
stream_bytes_avail(void *opaque, struct mbuf *mq)
{
  stream_t *s = opaque;
  pthread_mutex_lock(&s->s_recv_mutex);
  mbuf_appendq(&s->s_recv_buf, mq);
  pthread_cond_signal(&s->s_recv_cond);
  pthread_mutex_unlock(&s->s_recv_mutex);
}


stream_t *
stream_connect(const char *hostname, int port, int timeout_ms,
               char *errbuf, size_t errlen, int flags)
{
  if(flags & STREAM_DEBUG)
    trace(LOG_DEBUG, "stream: Connecting to %s:%d", hostname, port);
  int fd = dialfd(hostname, port, timeout_ms, errbuf, errlen,
                  flags & STREAM_DEBUG);
  if(flags & STREAM_DEBUG)
    trace(LOG_DEBUG, "stream: Connect %s:%d : %s",
          hostname, port, fd == -1 ? strerror(errno) : "OK");
  if(fd == -1)
    return NULL;
  stream_t *s = calloc(1, sizeof(stream_t));
  atomic_set(&s->s_refcount, 2);

  mbuf_init(&s->s_recv_buf);
  pthread_cond_init(&s->s_recv_cond, NULL);
  pthread_mutex_init(&s->s_recv_mutex, NULL);

  asyncio_sslctx_t *sslctx = NULL;

  if(flags & STREAM_CONNECT_F_SSL) {
    if(flags & STREAM_DEBUG)
      trace(LOG_DEBUG, "stream: Initializing TLS context for %s:%d", hostname, port);
    sslctx = asyncio_sslctx_client();
    if(flags & STREAM_DEBUG)
      trace(LOG_DEBUG, "stream: Initialized TLS context for %s:%d", hostname, port);
  }

  int asyncio_flags = ASYNCIO_FLAG_THREAD_SAFE;
  if(!(flags & STREAM_CONNECT_F_SSL_DONT_VERIFY))
    asyncio_flags |= ASYNCIO_FLAG_SSL_VERIFY_CERT;

  s->s_af = asyncio_stream(fd, stream_bytes_avail, stream_error,
                           s, asyncio_flags, sslctx, hostname, hostname,
                           NULL);
  if(sslctx != NULL)
    asyncio_sslctx_free(sslctx);

  if(flags & STREAM_DEBUG)
    trace(LOG_DEBUG, "stream: Stream for %s:%d initialized", hostname, port);

  return s;
}


ssize_t
stream_write(stream_t *s, const void *data, size_t len)
{
  if(asyncio_send(s->s_af, data, len, 0) == -1) {
    errno = ECONNRESET;
    return -1;
  }
  return len;
}


ssize_t
stream_read_timeout(stream_t *s, void *data, size_t len, int flags,
                    int64_t deadline)
{
  struct timespec ts, *tsp = NULL;

  if(deadline) {
    ts.tv_sec  =  deadline / 1000000;
    ts.tv_nsec = (deadline % 1000000) * 1000;
    tsp = &ts;
  }

  pthread_mutex_lock(&s->s_recv_mutex);
  while(1) {
    if(s->s_recv_buf.mq_size == 0 && s->s_eos) {
      if(flags == 0) {
        pthread_mutex_unlock(&s->s_recv_mutex);
        return 0;
      }

      errno = s->s_error;
      pthread_mutex_unlock(&s->s_recv_mutex);
      return -1;
    }

    int do_wait = 0;
    if(flags & STREAM_READ_F_ALL) {
      if(s->s_recv_buf.mq_size < len) {
        do_wait = 1;
      }
    } else {
      if(s->s_recv_buf.mq_size == 0) {
        do_wait = 1;
      }
    }

    if(do_wait) {
      if(tsp) {
        int r = pthread_cond_timedwait(&s->s_recv_cond, &s->s_recv_mutex, tsp);
        if(r) {
          errno = r;
          pthread_mutex_unlock(&s->s_recv_mutex);
          return -1;
        }
      } else {
        pthread_cond_wait(&s->s_recv_cond, &s->s_recv_mutex);
      }
      continue;
    }

    int r = MIN(s->s_recv_buf.mq_size, len);
    mbuf_read(&s->s_recv_buf, data, r);
    pthread_mutex_unlock(&s->s_recv_mutex);
    return r;
  }
}

ssize_t
stream_read(stream_t *s, void *data, size_t len, int flags)
{
  return stream_read_timeout(s, data, len, flags, 0);
}

void
stream_close(stream_t *s)
{
  asyncio_shutdown(s->s_af);
  stream_release(s);
}


void
stream_shutdown(stream_t *s)
{
  asyncio_shutdown(s->s_af);
}
