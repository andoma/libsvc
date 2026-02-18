#include <string.h>
#include <sys/param.h>
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <poll.h>
#include <sys/socket.h>
#include <time.h>

#include "bearssl.h"

#include "stream.h"
#include "dial.h"
#include "trace.h"

#include "ta_certs.h"

// x509 "no anchor" validator — wraps br_x509_minimal, converts
// BR_ERR_X509_NOT_TRUSTED to success (for STREAM_CONNECT_F_SSL_DONT_VERIFY)

typedef struct {
  const br_x509_class *vtable;
  const br_x509_class **inner;
} x509_noanchor_context;

static void
xwc_start_chain(const br_x509_class **ctx, const char *server_name)
{
  x509_noanchor_context *xwc = (x509_noanchor_context *)ctx;
  (*xwc->inner)->start_chain(xwc->inner, server_name);
}

static void
xwc_start_cert(const br_x509_class **ctx, uint32_t length)
{
  x509_noanchor_context *xwc = (x509_noanchor_context *)ctx;
  (*xwc->inner)->start_cert(xwc->inner, length);
}

static void
xwc_append(const br_x509_class **ctx, const unsigned char *buf, size_t len)
{
  x509_noanchor_context *xwc = (x509_noanchor_context *)ctx;
  (*xwc->inner)->append(xwc->inner, buf, len);
}

static void
xwc_end_cert(const br_x509_class **ctx)
{
  x509_noanchor_context *xwc = (x509_noanchor_context *)ctx;
  (*xwc->inner)->end_cert(xwc->inner);
}

static unsigned
xwc_end_chain(const br_x509_class **ctx)
{
  x509_noanchor_context *xwc = (x509_noanchor_context *)ctx;
  unsigned r = (*xwc->inner)->end_chain(xwc->inner);
  if(r == BR_ERR_X509_NOT_TRUSTED)
    r = 0;
  return r;
}

static const br_x509_pkey *
xwc_get_pkey(const br_x509_class *const *ctx, unsigned *usages)
{
  x509_noanchor_context *xwc = (x509_noanchor_context *)ctx;
  return (*xwc->inner)->get_pkey(xwc->inner, usages);
}

static const br_x509_class x509_noanchor_vtable = {
  sizeof(x509_noanchor_context),
  xwc_start_chain,
  xwc_start_cert,
  xwc_append,
  xwc_end_cert,
  xwc_end_chain,
  xwc_get_pkey
};


struct stream {
  int s_fd;
  int s_ssl;
  int s_flags;

  br_ssl_client_context s_sc;
  br_x509_minimal_context s_xc;
  unsigned char *s_iobuf;
  pthread_mutex_t s_ssl_mutex;

  x509_noanchor_context s_xwc;
};


static ssize_t
write_all(int fd, const void *data, size_t len)
{
  const unsigned char *p = data;
  size_t remaining = len;
  while(remaining > 0) {
    ssize_t r = write(fd, p, remaining);
    if(r < 0) {
      if(errno == EINTR)
        continue;
      return -1;
    }
    p += r;
    remaining -= r;
  }
  return len;
}


static int
compute_poll_timeout(int64_t deadline, int connect_flags)
{
  if(deadline == 0)
    return -1;

  struct timespec ts;
  if(connect_flags & STREAM_CLOCK_MONOTONIC)
    clock_gettime(CLOCK_MONOTONIC, &ts);
  else
    clock_gettime(CLOCK_REALTIME, &ts);

  int64_t now = ts.tv_sec * (int64_t)1000000 + ts.tv_nsec / 1000;
  int64_t remaining_us = deadline - now;
  if(remaining_us <= 0)
    return 0;

  int64_t remaining_ms = remaining_us / 1000;
  if(remaining_ms > INT32_MAX)
    return INT32_MAX;
  return (int)remaining_ms;
}


static int
ssl_handshake(stream_t *s, char *errbuf, size_t errlen)
{
  br_ssl_engine_context *eng = &s->s_sc.eng;

  for(;;) {
    unsigned state = br_ssl_engine_current_state(eng);

    if(state & BR_SSL_CLOSED) {
      int err = br_ssl_engine_last_error(eng);
      snprintf(errbuf, errlen, "TLS handshake failed (error %d)", err);
      return -1;
    }

    if(state & BR_SSL_SENDREC) {
      unsigned char *buf;
      size_t len;
      buf = br_ssl_engine_sendrec_buf(eng, &len);
      ssize_t wlen = write_all(s->s_fd, buf, len);
      if(wlen < 0) {
        snprintf(errbuf, errlen, "TLS handshake write failed: %s",
                 strerror(errno));
        return -1;
      }
      br_ssl_engine_sendrec_ack(eng, len);
      continue;
    }

    if(state & (BR_SSL_SENDAPP | BR_SSL_RECVAPP))
      return 0;

    if(state & BR_SSL_RECVREC) {
      unsigned char *buf;
      size_t len;
      buf = br_ssl_engine_recvrec_buf(eng, &len);
      ssize_t rlen = read(s->s_fd, buf, len);
      if(rlen <= 0) {
        if(rlen == 0)
          snprintf(errbuf, errlen, "TLS handshake: connection closed");
        else
          snprintf(errbuf, errlen, "TLS handshake read failed: %s",
                   strerror(errno));
        return -1;
      }
      br_ssl_engine_recvrec_ack(eng, rlen);
      continue;
    }

    br_ssl_engine_flush(eng, 0);
  }
}


static ssize_t
plain_read_timeout(int fd, void *data, size_t len, int read_flags,
                   int64_t deadline, int connect_flags)
{
  uint8_t *dst = data;
  size_t total = 0;

  while(total < len) {
    int timeout_ms = compute_poll_timeout(deadline, connect_flags);
    if(timeout_ms == 0 && total == 0 && deadline != 0) {
      errno = ETIMEDOUT;
      return -1;
    }

    struct pollfd pfd = { .fd = fd, .events = POLLIN };
    int pr = poll(&pfd, 1, timeout_ms);
    if(pr == 0) {
      if(total > 0)
        return total;
      errno = ETIMEDOUT;
      return -1;
    }
    if(pr < 0) {
      if(errno == EINTR)
        continue;
      return total > 0 ? (ssize_t)total : -1;
    }

    ssize_t r = read(fd, dst + total, len - total);
    if(r < 0) {
      if(errno == EINTR)
        continue;
      return total > 0 ? (ssize_t)total : -1;
    }
    if(r == 0)
      return total;

    total += r;
    if(!(read_flags & STREAM_READ_F_ALL))
      return total;
  }
  return total;
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
          hostname, port, fd == -1 ? errbuf : "OK");

  if(fd == -1)
    return NULL;

  stream_t *s = calloc(1, sizeof(stream_t));
  s->s_fd = fd;
  s->s_flags = flags;

  if(!(flags & STREAM_CONNECT_F_SSL))
    return s;

  s->s_ssl = 1;
  pthread_mutex_init(&s->s_ssl_mutex, NULL);

  if(flags & STREAM_DEBUG)
    trace(LOG_DEBUG, "stream: Initializing TLS for %s:%d", hostname, port);

  br_ssl_client_init_full(&s->s_sc, &s->s_xc, TAs, TAs_NUM);

  s->s_iobuf = malloc(BR_SSL_BUFSIZE_BIDI);
  br_ssl_engine_set_buffer(&s->s_sc.eng, s->s_iobuf, BR_SSL_BUFSIZE_BIDI, 1);

  if(flags & STREAM_CONNECT_F_SSL_DONT_VERIFY) {
    s->s_xwc.vtable = &x509_noanchor_vtable;
    s->s_xwc.inner = &s->s_xc.vtable;
    br_ssl_engine_set_x509(&s->s_sc.eng, &s->s_xwc.vtable);
  }

  br_ssl_client_reset(&s->s_sc, hostname, 0);

  if(ssl_handshake(s, errbuf, errlen) < 0) {
    if(flags & STREAM_DEBUG)
      trace(LOG_DEBUG, "stream: TLS handshake failed for %s:%d: %s",
            hostname, port, errbuf);
    pthread_mutex_destroy(&s->s_ssl_mutex);
    free(s->s_iobuf);
    close(fd);
    free(s);
    return NULL;
  }

  if(flags & STREAM_DEBUG)
    trace(LOG_DEBUG, "stream: TLS established for %s:%d", hostname, port);

  return s;
}


ssize_t
stream_write(stream_t *s, const void *data, size_t len)
{
  if(!s->s_ssl)
    return write_all(s->s_fd, data, len);

  const unsigned char *src = data;
  size_t remaining = len;

  while(remaining > 0) {
    unsigned char sendbuf[BR_SSL_BUFSIZE_OUTPUT];
    size_t sendlen = 0;

    pthread_mutex_lock(&s->s_ssl_mutex);

    unsigned state = br_ssl_engine_current_state(&s->s_sc.eng);
    if(state & BR_SSL_CLOSED) {
      pthread_mutex_unlock(&s->s_ssl_mutex);
      errno = ECONNRESET;
      return -1;
    }

    unsigned char *buf;
    size_t avail;
    buf = br_ssl_engine_sendapp_buf(&s->s_sc.eng, &avail);
    if(buf == NULL || avail == 0) {
      pthread_mutex_unlock(&s->s_ssl_mutex);
      errno = ECONNRESET;
      return -1;
    }

    size_t chunk = remaining < avail ? remaining : avail;
    memcpy(buf, src, chunk);
    br_ssl_engine_sendapp_ack(&s->s_sc.eng, chunk);
    br_ssl_engine_flush(&s->s_sc.eng, 0);

    buf = br_ssl_engine_sendrec_buf(&s->s_sc.eng, &sendlen);
    if(buf != NULL && sendlen > 0) {
      memcpy(sendbuf, buf, sendlen);
      br_ssl_engine_sendrec_ack(&s->s_sc.eng, sendlen);
    }

    pthread_mutex_unlock(&s->s_ssl_mutex);

    if(sendlen > 0) {
      if(write_all(s->s_fd, sendbuf, sendlen) < 0) {
        errno = ECONNRESET;
        return -1;
      }
    }

    src += chunk;
    remaining -= chunk;
  }
  return len;
}


ssize_t
stream_read_timeout(stream_t *s, void *data, size_t len, int flags,
                    int64_t deadline)
{
  if(!s->s_ssl)
    return plain_read_timeout(s->s_fd, data, len, flags, deadline, s->s_flags);

  unsigned char *dst = data;
  size_t total = 0;

  while(total < len) {
    // Check for buffered plaintext in the engine
    pthread_mutex_lock(&s->s_ssl_mutex);

    unsigned char *buf;
    size_t avail;
    buf = br_ssl_engine_recvapp_buf(&s->s_sc.eng, &avail);
    if(buf != NULL && avail > 0) {
      size_t want = len - total;
      size_t copy = want < avail ? want : avail;
      memcpy(dst + total, buf, copy);
      br_ssl_engine_recvapp_ack(&s->s_sc.eng, copy);
      total += copy;
      pthread_mutex_unlock(&s->s_ssl_mutex);
      if(!(flags & STREAM_READ_F_ALL) || total >= len)
        return total;
      continue;
    }

    unsigned state = br_ssl_engine_current_state(&s->s_sc.eng);
    if(state & BR_SSL_CLOSED) {
      pthread_mutex_unlock(&s->s_ssl_mutex);
      if(total > 0)
        return total;
      int err = br_ssl_engine_last_error(&s->s_sc.eng);
      if(err == 0 || flags == 0)
        return 0;
      errno = ECONNRESET;
      return -1;
    }

    pthread_mutex_unlock(&s->s_ssl_mutex);

    // Poll + read from socket
    int timeout_ms = compute_poll_timeout(deadline, s->s_flags);
    if(timeout_ms == 0 && total == 0 && deadline != 0) {
      errno = ETIMEDOUT;
      return -1;
    }

    struct pollfd pfd = { .fd = s->s_fd, .events = POLLIN };
    int pr = poll(&pfd, 1, timeout_ms);
    if(pr == 0) {
      if(total > 0)
        return total;
      errno = ETIMEDOUT;
      return -1;
    }
    if(pr < 0) {
      if(errno == EINTR)
        continue;
      return total > 0 ? (ssize_t)total : -1;
    }

    unsigned char recvtmp[BR_SSL_BUFSIZE_INPUT];
    ssize_t rlen = read(s->s_fd, recvtmp, sizeof(recvtmp));
    if(rlen < 0) {
      if(errno == EINTR)
        continue;
      return total > 0 ? (ssize_t)total : -1;
    }
    if(rlen == 0) {
      if(total > 0)
        return total;
      if(flags == 0)
        return 0;
      errno = ECONNRESET;
      return -1;
    }

    // Feed data to BearSSL engine
    pthread_mutex_lock(&s->s_ssl_mutex);

    size_t fed = 0;
    while(fed < (size_t)rlen) {
      buf = br_ssl_engine_recvrec_buf(&s->s_sc.eng, &avail);
      if(buf == NULL || avail == 0)
        break;
      size_t chunk = ((size_t)rlen - fed) < avail
        ? ((size_t)rlen - fed) : avail;
      memcpy(buf, recvtmp + fed, chunk);
      br_ssl_engine_recvrec_ack(&s->s_sc.eng, chunk);
      fed += chunk;
    }

    // Check if engine decrypted any application data
    buf = br_ssl_engine_recvapp_buf(&s->s_sc.eng, &avail);
    if(buf != NULL && avail > 0) {
      size_t want = len - total;
      size_t copy = want < avail ? want : avail;
      memcpy(dst + total, buf, copy);
      br_ssl_engine_recvapp_ack(&s->s_sc.eng, copy);
      total += copy;
    }

    pthread_mutex_unlock(&s->s_ssl_mutex);

    if(total > 0 && !(flags & STREAM_READ_F_ALL))
      return total;
  }
  return total;
}


ssize_t
stream_read(stream_t *s, void *data, size_t len, int flags)
{
  return stream_read_timeout(s, data, len, flags, 0);
}


void
stream_close(stream_t *s)
{
  if(s->s_ssl) {
    // Best-effort close_notify
    unsigned char closebuf[128];
    size_t closelen = 0;

    pthread_mutex_lock(&s->s_ssl_mutex);
    br_ssl_engine_close(&s->s_sc.eng);

    unsigned char *buf;
    size_t len;
    buf = br_ssl_engine_sendrec_buf(&s->s_sc.eng, &len);
    if(buf != NULL && len > 0 && len <= sizeof(closebuf)) {
      memcpy(closebuf, buf, len);
      closelen = len;
      br_ssl_engine_sendrec_ack(&s->s_sc.eng, len);
    }
    pthread_mutex_unlock(&s->s_ssl_mutex);

    if(closelen > 0)
      write_all(s->s_fd, closebuf, closelen);

    pthread_mutex_destroy(&s->s_ssl_mutex);
    free(s->s_iobuf);
  }

  close(s->s_fd);
  free(s);
}


void
stream_shutdown(stream_t *s, int stop_reader)
{
  if(stop_reader)
    shutdown(s->s_fd, SHUT_RDWR);
}
