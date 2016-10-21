/******************************************************************************
* Copyright (C) 2008 - 2014 Andreas Öman
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

#ifdef linux
#include <sys/sendfile.h>
#endif

#include <sys/param.h>
#include <pthread.h>
#include <netdb.h>
#include <poll.h>
#include <assert.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <fcntl.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

#include "tcp.h"

static SSL_CTX *ssl_ctx;
static pthread_mutex_t *ssl_locks;


struct tcp_stream {
  int ts_fd;
  char ts_nonblock;

  SSL *ts_ssl;

  htsbuf_queue_t ts_spill;
  htsbuf_queue_t ts_sendq;

  int (*ts_write)(struct tcp_stream *ts, const void *data, int len);

  int (*ts_read)(struct tcp_stream *ts, void *data, int len, int waitall);

  int ts_read_status;
  int ts_write_status;

};


/**
 *
 */
int
tcp_get_errno(tcp_stream_t *ts)
{
  int err = 0;
  socklen_t len = sizeof(err);
  getsockopt(ts->ts_fd, SOL_SOCKET, SO_ERROR, &err, &len);
  return err;
}


/**
 *
 */
void
tcp_close(tcp_stream_t *ts)
{
  if(ts->ts_ssl != NULL) {
    SSL_shutdown(ts->ts_ssl);
    SSL_free(ts->ts_ssl);
  }

  htsbuf_queue_flush(&ts->ts_spill);
  htsbuf_queue_flush(&ts->ts_sendq);
  if(ts->ts_fd != -1) {
    int r = close(ts->ts_fd);
    if(r)
      printf("Close failed!\n");
  }
  free(ts);
}


/**
 *
 */
int
tcp_steal_fd(tcp_stream_t *ts)
{
  int fd = ts->ts_fd;
  ts->ts_fd = -1;
  return fd;
}

/**
 *
 */
static int
os_write_try(tcp_stream_t *ts)
{
  htsbuf_data_t *hd;
  htsbuf_queue_t *q = &ts->ts_sendq;
  int len;

  while((hd = TAILQ_FIRST(&q->hq_q)) != NULL) {

    len = hd->hd_data_len - hd->hd_data_off;
    assert(len > 0);

    int r = write(ts->ts_fd, hd->hd_data + hd->hd_data_off, len);
    if(r < 0 && errno == EINTR)
      continue;

    if(r < 1)
      return -1;

    hd->hd_data_off += r;

    if(r != len)
      return -1;

    assert(hd->hd_data_off == hd->hd_data_len);

    TAILQ_REMOVE(&q->hq_q, hd, hd_link);
    free(hd->hd_data);
    free(hd);
  }
  return 0;
}


/**
 *
 */
static int
safe_write(int fd, const void *data, int len)
{
  int written = 0;

  while(written < len) {
    int r = write(fd, data + written, len - written);
    if(r < 0 && errno == EINTR)
      continue;

    if(r <= 0)
      return written;

    written += r;
  }
  return written;
}


/**
 *
 */
static int
os_read(struct tcp_stream *ts, void *data, int len, int waitall)
{
  while(1) {
    int r = recv(ts->ts_fd, data, len, waitall ? MSG_WAITALL : 0);

    if(r < 0 && errno == EINTR)
      continue;

    return r;
  }
}


/**
 *
 */
static int
os_write(struct tcp_stream *ts, const void *data, int len)
{
  if(!ts->ts_nonblock)
    return safe_write(ts->ts_fd, data, len);

  htsbuf_append(&ts->ts_sendq, data, len);
  os_write_try(ts);
  return len;
}


/**
 *
 */
static int
ssl_read(struct tcp_stream *ts, void *data, int len, int waitall)
{
  assert(waitall == 0); // Not supported atm.

  if(ts->ts_write_status == SSL_ERROR_WANT_READ) {
    errno = EAGAIN;
    return -1;
  }

  ts->ts_read_status = 0;
  int r = SSL_read(ts->ts_ssl, data, len);
  int err = SSL_get_error(ts->ts_ssl, r);
  switch(err) {
  case SSL_ERROR_NONE:
    return r;

  case SSL_ERROR_ZERO_RETURN:
    errno = ECONNRESET;
    return -1;

  case SSL_ERROR_WANT_READ:
  case SSL_ERROR_WANT_WRITE:
    ts->ts_read_status = err;
    errno = EAGAIN;
    return -1;

  default:
    errno = EBADMSG;
    return -1;
  }
}


/**
 *
 */
static void
ssl_write_try(tcp_stream_t *ts)
{
  htsbuf_data_t *hd;
  htsbuf_queue_t *q = &ts->ts_sendq;
  int len;

  ts->ts_write_status = 0;

  while((hd = TAILQ_FIRST(&q->hq_q)) != NULL) {

    len = hd->hd_data_len - hd->hd_data_off;
    assert(len > 0);

    int r = SSL_write(ts->ts_ssl, hd->hd_data + hd->hd_data_off, len);
    int err = SSL_get_error(ts->ts_ssl, r);

    switch(err) {
    case SSL_ERROR_NONE:
      hd->hd_data_off += r;

      assert(hd->hd_data_off <= hd->hd_data_len);

      if(hd->hd_data_off == hd->hd_data_len) {
        TAILQ_REMOVE(&q->hq_q, hd, hd_link);
        free(hd->hd_data);
        free(hd);
      }
      continue;

    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE:
      ts->ts_write_status = err;
      return;

    default:
      return;
    }
  }
}


/**
 *
 */
static int
ssl_write(struct tcp_stream *ts, const void *data, int len)
{
  if(!ts->ts_nonblock) {
    int r = SSL_write(ts->ts_ssl, data, len);
    if(r > 0)
      return r;
    errno = EBADMSG;
    return -1;
  }

  htsbuf_append(&ts->ts_sendq, data, len);

  if(ts->ts_read_status != SSL_ERROR_WANT_WRITE)
    ssl_write_try(ts);

  return len;
}


/**
 *
 */
void
tcp_prepare_poll(tcp_stream_t *ts, struct pollfd *pfd)
{
  assert(ts->ts_nonblock);

  pfd->fd = ts->ts_fd;
  pfd->events = POLLERR | POLLHUP;

  if(ts->ts_ssl != NULL) {

    if(ts->ts_read_status == SSL_ERROR_WANT_WRITE) {
      pfd->events |= POLLOUT;
    } else {
      pfd->events |= POLLIN;
      ssl_write_try(ts);
    }

    if(ts->ts_write_status == SSL_ERROR_WANT_WRITE)
      pfd->events |= POLLOUT;
    else if(ts->ts_write_status == SSL_ERROR_WANT_READ)
      pfd->events |= POLLIN;

  } else {

    pfd->events |= POLLIN;
    if(os_write_try(ts))
      pfd->events |= POLLOUT;
  }
}


/**
 *
 */
int
tcp_can_read(tcp_stream_t *ts, struct pollfd *pfd)
{
  if(ts->ts_ssl == NULL)
    return pfd->revents & POLLIN;

  if(ts->ts_write_status == SSL_ERROR_WANT_READ)
    return 0;

  return 1;
}


/**
 *
 */
tcp_stream_t *
tcp_stream_create_from_fd(int fd)
{
  tcp_stream_t *ts = calloc(1, sizeof(tcp_stream_t));

  ts->ts_fd = fd;
  htsbuf_queue_init(&ts->ts_spill, INT32_MAX);
  htsbuf_queue_init(&ts->ts_sendq, INT32_MAX);

  ts->ts_write = os_write;
  ts->ts_read  = os_read;

  return ts;
}


/**
 *
 */
int
tcp_sendfile(tcp_stream_t *ts, int fd, int64_t bytes)
{
#if defined(__APPLE__)
  off_t len = bytes;
  return sendfile(fd, ts->ts_fd, 0, &len, NULL, 0);
#elif defined(linux)
  while(bytes > 0) {
    int chunk = MIN(1024 * 1024 * 1024, bytes);
    int r = sendfile(ts->ts_fd, fd, NULL, chunk);
    if(r < 1)
      return -1;
    bytes -= r;
  }
#else
#error Need sendfile implementation
#endif

  return 0;
}


/**
 *
 */
int
tcp_write(tcp_stream_t *ts, const void *buf, const size_t bufsize)
{
  return ts->ts_write(ts, buf, bufsize);
}


/**
 *
 */
void
tcp_nonblock(tcp_stream_t *ts, int on)
{
  ts->ts_nonblock = on;
  int flags = fcntl(ts->ts_fd, F_GETFL);

  if(on)
    flags |= O_NONBLOCK;
  else
    flags &= ~O_NONBLOCK;

  fcntl(ts->ts_fd, F_SETFL, flags);
}



/**
 *
 */
int
tcp_write_queue(tcp_stream_t *ts, htsbuf_queue_t *q)
{
  htsbuf_data_t *hd;
  int l, err = 0;

  while((hd = TAILQ_FIRST(&q->hq_q)) != NULL) {
    TAILQ_REMOVE(&q->hq_q, hd, hd_link);

    while(!err) {

      l = hd->hd_data_len - hd->hd_data_off;
      if(l == 0)
        break;
      int r = ts->ts_write(ts, hd->hd_data + hd->hd_data_off, l);
      if(r > 0) {
        hd->hd_data_off += r;
      } else {
        err = 1;
      }
    }
    free(hd->hd_data);
    free(hd);
  }
  q->hq_size = 0;
  return err;
}


/**
 *
 */
static int
tcp_fill_htsbuf_from_fd(tcp_stream_t *ts, htsbuf_queue_t *hq)
{
  htsbuf_data_t *hd = TAILQ_LAST(&hq->hq_q, htsbuf_data_queue);
  int c;

  if(hd != NULL) {
    /* Fill out any previous buffer */
    c = hd->hd_data_size - hd->hd_data_len;

    if(c > 0) {

      c = ts->ts_read(ts, hd->hd_data + hd->hd_data_len, c, 0);
      if(c < 1)
	return -1;

      hd->hd_data_len += c;
      hq->hq_size += c;
      return 0;
    }
  }

  hd = malloc(sizeof(htsbuf_data_t));

  hd->hd_data_size = 1000;
  hd->hd_data = malloc(hd->hd_data_size);

  c = ts->ts_read(ts, hd->hd_data, hd->hd_data_size, 0);
  if(c < 1) {
    free(hd->hd_data);
    free(hd);
    return -1;
  }
  hd->hd_data_len = c;
  hd->hd_data_off = 0;
  TAILQ_INSERT_TAIL(&hq->hq_q, hd, hd_link);
  hq->hq_size += c;
  return 0;
}


/**
 *
 */
int
tcp_read_line(tcp_stream_t *ts, char *buf, const size_t bufsize)
{
  int len;

  while(1) {
    len = htsbuf_find(&ts->ts_spill, 0xa);

    if(len == -1) {
      if(tcp_fill_htsbuf_from_fd(ts, &ts->ts_spill) < 0)
	return -1;
      continue;
    }
    
    if(len >= bufsize - 1)
      return -1;

    htsbuf_read(&ts->ts_spill, buf, len);
    buf[len] = 0;
    while(len > 0 && buf[len - 1] < 32)
      buf[--len] = 0;
    htsbuf_drop(&ts->ts_spill, 1); /* Drop the \n */
    return 0;
  }
}



/**
 *
 */
int
tcp_read_data(tcp_stream_t *ts, char *buf, const size_t bufsize)
{
  int x, tot = htsbuf_read(&ts->ts_spill, buf, bufsize);

  if(tot == bufsize)
    return 0;

  x = ts->ts_read(ts, buf + tot, bufsize - tot, 1);
  if(x != bufsize - tot)
    return -1;

  return 0;
}


/**
 *
 */
int
tcp_read(tcp_stream_t *ts, void *buf, size_t len)
{
  return ts->ts_read(ts, buf, len, 0);
}


/**
 *
 */
htsbuf_queue_t *
tcp_read_buffered(tcp_stream_t *ts)
{
  if(tcp_fill_htsbuf_from_fd(ts, &ts->ts_spill) < 0) {
    if(errno == EAGAIN)
      return &ts->ts_spill;

    return NULL;
  }

  return &ts->ts_spill;
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
    if(match)
      return 0;
  }
  snprintf(errbuf, errlen, "SSL: Hostname mismatch");
  return -1;
}


/**
 *
 */
tcp_stream_t *
tcp_stream_create_ssl_from_fd(int fd, const char *hostname,
                              const tcp_ssl_info_t *tsi,
                              char *errbuf, size_t errlen)
{
  char errmsg[120];

  tcp_stream_t *ts = calloc(1, sizeof(tcp_stream_t));
  ts->ts_fd = fd;

  if((ts->ts_ssl = SSL_new(ssl_ctx)) == NULL)
    goto bad_ssl;

  SSL_set_tlsext_host_name(ts->ts_ssl, hostname);


  if(SSL_set_fd(ts->ts_ssl, fd) == 0)
    goto bad_ssl;

  if(tsi->key != NULL) {
    BIO *cbio = BIO_new_mem_buf((char *)tsi->key, -1);
    EVP_PKEY *key = PEM_read_bio_PrivateKey(cbio, NULL, NULL, NULL);
    BIO_free(cbio);
    if(key == NULL) {
      snprintf(errbuf, errlen, "Unable to load private key");
      goto bad;
    }

    SSL_use_PrivateKey(ts->ts_ssl, key);
    EVP_PKEY_free(key);
  }

  if(tsi->cert != NULL) {
    BIO *cbio = BIO_new_mem_buf((char *)tsi->cert, -1);
    X509 *cert = PEM_read_bio_X509(cbio, NULL, 0, NULL);
    BIO_free(cbio);

    if(cert == NULL) {
      snprintf(errbuf, errlen, "Unable to load certificate");
      goto bad;
    }

    SSL_use_certificate(ts->ts_ssl, cert);
    X509_free(cert);
  }

  if(SSL_connect(ts->ts_ssl) <= 0) {
    goto bad_ssl;
  }

  SSL_set_mode(ts->ts_ssl, SSL_MODE_AUTO_RETRY);

  if(!tsi->no_verify) {

    X509 *peer = SSL_get_peer_certificate(ts->ts_ssl);
    if(peer == NULL) {
      goto bad_ssl;
    }

    int err = SSL_get_verify_result(ts->ts_ssl);
    if(err != X509_V_OK) {
      snprintf(errbuf, errlen, "Certificate error: %s",
               X509_verify_cert_error_string(err));
      X509_free(peer);
      goto bad;
    }

    if(verify_hostname(hostname, peer, errbuf, errlen)) {
      X509_free(peer);
      goto bad;
    }

    X509_free(peer);
  }

  ts->ts_fd = fd;
  htsbuf_queue_init(&ts->ts_spill, INT32_MAX);
  htsbuf_queue_init(&ts->ts_sendq, INT32_MAX);

  ts->ts_write = ssl_write;
  ts->ts_read  = ssl_read;
  return ts;

 bad_ssl:
  ERR_error_string(ERR_get_error(), errmsg);
  snprintf(errbuf, errlen, "SSL: %s", errmsg);
 bad:
  tcp_close(ts);
  return NULL;
}




/**
 *
 */
static unsigned long
ssl_tid_fn(void)
{
  return (unsigned long)pthread_self();
}

static void
ssl_lock_fn(int mode, int n, const char *file, int line)
{
  if(mode & CRYPTO_LOCK)
    pthread_mutex_lock(&ssl_locks[n]);
  else if(mode & CRYPTO_UNLOCK)
    pthread_mutex_unlock(&ssl_locks[n]);
}


/**
 *
 */
void
tcp_init1(const char *extra_ca, int init_ssl)
{
  if(init_ssl) {
    SSL_library_init();
    SSL_load_error_strings();

    int i, n = CRYPTO_num_locks();
    ssl_locks = malloc(sizeof(pthread_mutex_t) * n);
    for(i = 0; i < n; i++)
      pthread_mutex_init(&ssl_locks[i], NULL);

    CRYPTO_set_locking_callback(ssl_lock_fn);
    CRYPTO_set_id_callback(ssl_tid_fn);
  }

  ssl_ctx = SSL_CTX_new(TLSv1_2_client_method());

  if(!SSL_CTX_load_verify_locations(ssl_ctx, NULL, "/etc/ssl/certs"))
    exit(1);

  if(extra_ca != NULL) {
    BIO *cbio = BIO_new_mem_buf((char *)extra_ca, -1);
    X509 *cert = PEM_read_bio_X509(cbio, NULL, 0, NULL);
    BIO_free(cbio);

    if(cert == NULL) {
      fprintf(stderr, "Unable to load extra cert\n");
      exit(1);
    }

    X509_STORE *store = SSL_CTX_get_cert_store(ssl_ctx);
    X509_STORE_add_cert(store, cert);
  }

  SSL_CTX_set_verify_depth(ssl_ctx, 3);
}


/**
 *
 */
void
tcp_init(void)
{
  tcp_init1(NULL, 1);
}
