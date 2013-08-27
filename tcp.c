/*
 *  Copyright (C) 2013 Andreas Öman
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <pthread.h>
#include <netdb.h>
#include <sys/epoll.h>
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

#include "tcp.h"
#include "trace.h"

/**
 *
 */
int
tcp_write_queue(int fd, htsbuf_queue_t *q)
{
  htsbuf_data_t *hd;
  int l, err = 0;

  while((hd = TAILQ_FIRST(&q->hq_q)) != NULL) {
    TAILQ_REMOVE(&q->hq_q, hd, hd_link);

    while(!err) {

      l = hd->hd_data_len - hd->hd_data_off;
      if(l == 0)
        break;
      int r = write(fd, hd->hd_data + hd->hd_data_off, l);
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
tcp_fill_htsbuf_from_fd(int fd, htsbuf_queue_t *hq)
{
  htsbuf_data_t *hd = TAILQ_LAST(&hq->hq_q, htsbuf_data_queue);
  int c;

  if(hd != NULL) {
    /* Fill out any previous buffer */
    c = hd->hd_data_size - hd->hd_data_len;

    if(c > 0) {

      c = read(fd, hd->hd_data + hd->hd_data_len, c);
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

  c = read(fd, hd->hd_data, hd->hd_data_size);
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
tcp_read_line(int fd, char *buf, const size_t bufsize, htsbuf_queue_t *spill)
{
  int len;

  while(1) {
    len = htsbuf_find(spill, 0xa);

    if(len == -1) {
      if(tcp_fill_htsbuf_from_fd(fd, spill) < 0)
	return -1;
      continue;
    }
    
    if(len >= bufsize - 1)
      return -1;

    htsbuf_read(spill, buf, len);
    buf[len] = 0;
    while(len > 0 && buf[len - 1] < 32)
      buf[--len] = 0;
    htsbuf_drop(spill, 1); /* Drop the \n */
    return 0;
  }
}



/**
 *
 */
int
tcp_read_data(int fd, char *buf, const size_t bufsize, htsbuf_queue_t *spill)
{
  int x, tot = htsbuf_read(spill, buf, bufsize);

  if(tot == bufsize)
    return 0;

  x = recv(fd, buf + tot, bufsize - tot, MSG_WAITALL);
  if(x != bufsize - tot)
    return -1;

  return 0;
}

/**
 *
 */
int
tcp_read(int fd, void *buf, size_t len)
{
  int x = recv(fd, buf, len, MSG_WAITALL);

  if(x == -1)
    return errno;
  if(x != len)
    return ECONNRESET;
  return 0;

}

/**
 *
 */
int
tcp_read_timeout(int fd, void *buf, size_t len, int timeout)
{
  int x, tot = 0;
  struct pollfd fds;

  assert(timeout > 0);

  fds.fd = fd;
  fds.events = POLLIN;
  fds.revents = 0;

  while(tot != len) {

    x = poll(&fds, 1, timeout);
    if(x == 0)
      return ETIMEDOUT;

    x = recv(fd, buf + tot, len - tot, MSG_DONTWAIT);
    if(x == -1) {
      if(errno == EAGAIN)
	continue;
      return errno;
    }

    if(x == 0)
      return ECONNRESET;

    tot += x;
  }

  return 0;

}


/**
 *
 */
static int tcp_server_epoll_fd;

typedef struct tcp_server {
  tcp_server_callback_t *start;
  void *opaque;
  int serverfd;
} tcp_server_t;

typedef struct tcp_server_launch_t {
  tcp_server_callback_t *start;
  void *opaque;
  int fd;
  struct sockaddr_in peer;
  struct sockaddr_in self;
} tcp_server_launch_t;


LIST_HEAD(tcp_thread_list, tcp_thread);

#define MAX_ACTIVE_THREADS 64
#define MAX_IDLE_THREADS   1

static int tcp_num_idle_threads;
static int tcp_num_active_threads;
static pthread_mutex_t tcp_thread_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t tcp_thread_cond = PTHREAD_COND_INITIALIZER;
static struct tcp_thread_list tcp_idle_threads;

/**
 *
 */
typedef struct tcp_thread {
  LIST_ENTRY(tcp_thread) tt_link;

  tcp_server_launch_t *tt_launch;
  pthread_cond_t tt_cond;
  pthread_t tt_tid;

} tcp_thread_t;


/**
 *
 */
static void *
tcp_trampoline(void *aux)
{
  tcp_thread_t *tt = aux;
  tcp_server_launch_t *tsl;

  while(1) {
    tsl = tt->tt_launch;
    tt->tt_launch = NULL;
    assert(tsl != NULL);
    tsl->start(tsl->fd, tsl->opaque, &tsl->peer, &tsl->self);
    free(tsl);

    pthread_mutex_lock(&tcp_thread_mutex);

    if(tcp_num_idle_threads == MAX_IDLE_THREADS) {
      tcp_num_active_threads--;
      pthread_mutex_unlock(&tcp_thread_mutex);
      break;
    }

    tcp_num_idle_threads++;
    LIST_INSERT_HEAD(&tcp_idle_threads, tt, tt_link);
    pthread_cond_signal(&tcp_thread_cond);

    while(tt->tt_launch == NULL)
      pthread_cond_wait(&tt->tt_cond, &tcp_thread_mutex);

    pthread_mutex_unlock(&tcp_thread_mutex);
  }
  return NULL;
}

/**
 *
 */
static void
tcp_server_start(tcp_server_launch_t *tsl)
{
  int val;

  val = 1;
  setsockopt(tsl->fd, SOL_SOCKET, SO_KEEPALIVE, &val, sizeof(val));

#ifdef TCP_KEEPIDLE
  val = 30;
  setsockopt(tsl->fd, IPPROTO_TCP, TCP_KEEPIDLE, &val, sizeof(val));
#endif

#ifdef TCP_KEEPINVL
  val = 15;
  setsockopt(tsl->fd, IPPROTO_TCP, TCP_KEEPINTVL, &val, sizeof(val));
#endif

#ifdef TCP_KEEPCNT
  val = 5;
  setsockopt(tsl->fd, IPPROTO_TCP, TCP_KEEPCNT, &val, sizeof(val));
#endif

  val = 1;
  setsockopt(tsl->fd, IPPROTO_TCP, TCP_NODELAY, &val, sizeof(val));

  pthread_mutex_lock(&tcp_thread_mutex);

  tcp_thread_t *tt;

  while(1) {
    tt = LIST_FIRST(&tcp_idle_threads);
    if(tt != NULL) {
      LIST_REMOVE(tt, tt_link);
      assert(tt->tt_launch == NULL);
      tt->tt_launch = tsl;
      tcp_num_idle_threads--;
      pthread_cond_signal(&tt->tt_cond);
      break;
    }

    assert(tcp_num_idle_threads == 0);

    if(tcp_num_active_threads >= MAX_ACTIVE_THREADS) {
      pthread_cond_wait(&tcp_thread_cond, &tcp_thread_mutex);
      continue;
    }

    tcp_num_active_threads++;

    tt = calloc(1, sizeof(tcp_thread_t));
    pthread_cond_init(&tt->tt_cond, NULL);
    tt->tt_launch = tsl;

    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_create(&tt->tt_tid, &attr, tcp_trampoline, tt);
    pthread_attr_destroy(&attr);
    break;
  }
  pthread_mutex_unlock(&tcp_thread_mutex);
}






/**
 *
 */
static void *
tcp_server_loop(void *aux)
{
  int r, i;
  struct epoll_event ev[1];
  tcp_server_t *ts;
  tcp_server_launch_t *tsl;
  socklen_t slen;

  while(1) {
    r = epoll_wait(tcp_server_epoll_fd, ev, sizeof(ev) / sizeof(ev[0]), -1);
    if(r == -1) {
      perror("tcp_server: epoll_wait");
      continue;
    }

    for(i = 0; i < r; i++) {
      ts = ev[i].data.ptr;

      if(ev[i].events & EPOLLHUP) {
	close(ts->serverfd);
	free(ts);
	continue;
      }

      if(ev[i].events & EPOLLIN) {
	tsl = malloc(sizeof(tcp_server_launch_t));
	tsl->start  = ts->start;
	tsl->opaque = ts->opaque;
	slen = sizeof(struct sockaddr_in);

	tsl->fd = accept(ts->serverfd, 
			 (struct sockaddr *)&tsl->peer, &slen);
	if(tsl->fd == -1) {
	  perror("accept");
	  free(tsl);
	  sleep(1);
	  continue;
	}


	slen = sizeof(struct sockaddr_in);
	if(getsockname(tsl->fd, (struct sockaddr *)&tsl->self, &slen)) {
	    close(tsl->fd);
	    free(tsl);
	    continue;
	}

        tcp_server_start(tsl);
      }
    }
  }
  return NULL;
}

/**
 *
 */
void *
tcp_server_create(int port, const char *bindaddr,
                  tcp_server_callback_t *start, void *opaque)
{
  int fd, x;
  struct epoll_event e;
  tcp_server_t *ts;
  struct sockaddr_in s;
  int one = 1;
  memset(&e, 0, sizeof(e));
  fd = socket(AF_INET, SOCK_STREAM, 0);
  if(fd == -1)
    return NULL;

  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(int));

  memset(&s, 0, sizeof(s));
  s.sin_family = AF_INET;
  s.sin_port = htons(port);
  if(bindaddr != NULL)
    s.sin_addr.s_addr = inet_addr(bindaddr);

  x = bind(fd, (struct sockaddr *)&s, sizeof(s));
  if(x < 0) {
    int x = errno;
    trace(LOG_ERR, "Unable to bind %s:%d -- %s", 
          bindaddr ?: "0.0.0.0", port, strerror(errno));
    close(fd);
    errno = x;
    return NULL;
  }

  listen(fd, 100);

  ts = malloc(sizeof(tcp_server_t));
  ts->serverfd = fd;
  ts->start = start;
  ts->opaque = opaque;

  
  e.events = EPOLLIN;
  e.data.ptr = ts;

  epoll_ctl(tcp_server_epoll_fd, EPOLL_CTL_ADD, fd, &e);
  return ts;
}

/**
 *
 */
void
tcp_server_init(void)
{
  pthread_t tid;

  tcp_server_epoll_fd = epoll_create(10);
  pthread_create(&tid, NULL, tcp_server_loop, NULL);
}


