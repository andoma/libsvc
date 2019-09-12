#include <sys/param.h>

#include <assert.h>
#include <pthread.h>
#include <stdlib.h>

#include "mbuf.h"
#include "fpipe.h"
#include "atomic.h"
#include "misc.h"

struct fpipe {

  pthread_mutex_t p_mutex;
  pthread_cond_t p_cond;

  mbuf_t p_buffer;

  int p_need;

  uint8_t p_open;
  uint8_t p_eof;
  uint8_t p_err;
};


static void
pipe_destroy(fpipe_t *p)
{
  assert(p->p_eof == 1 && p->p_open == 0);
  mbuf_clear(&p->p_buffer);
  pthread_mutex_unlock(&p->p_mutex);
  free(p);
}


static int
pipe_write(void *aux, const char *data, int size)
{
  fpipe_t *p = aux;

  pthread_mutex_lock(&p->p_mutex);
  while(p->p_buffer.mq_size > p->p_need && p->p_open)
    pthread_cond_wait(&p->p_cond, &p->p_mutex);
  mbuf_append(&p->p_buffer, data, size);
  pthread_cond_signal(&p->p_cond);
  pthread_mutex_unlock(&p->p_mutex);

  if(!p->p_open)
    return 0;
  return size;
}

static int
pipe_write_close(void *aux)
{
  fpipe_t *p = aux;
  pthread_mutex_lock(&p->p_mutex);
  p->p_eof = 1;
  if(p->p_open) {
    pthread_cond_signal(&p->p_cond);
    pthread_mutex_unlock(&p->p_mutex);
    return 0;
  }
  pipe_destroy(p);
  return 0;
}


#ifndef __APPLE__
static ssize_t
pipe_write2(void *cookie, const char *buf, size_t size)
{
  return pipe_write(cookie, buf, size);
}


static cookie_io_functions_t pipe_write_functions = {
  .write  = pipe_write2,
  .close = pipe_write_close,
};
#endif




static int
pipe_read(void *aux, char *data, int size)
{
  fpipe_t *p = aux;

  pthread_mutex_lock(&p->p_mutex);
  p->p_need = MIN(size, 65536);
  pthread_cond_signal(&p->p_cond);
  while(!p->p_eof && p->p_buffer.mq_size < p->p_need && !p->p_err) {
    pthread_cond_wait(&p->p_cond, &p->p_mutex);
  }

  if(p->p_err) {
    p->p_need = 0;
    pthread_mutex_unlock(&p->p_mutex);
    return -1;
  }

  int r = mbuf_read(&p->p_buffer, data, size);
  pthread_cond_signal(&p->p_cond);
  pthread_mutex_unlock(&p->p_mutex);
  return r;
}


static int
pipe_read_close(void *aux)
{
  fpipe_t *p = aux;

  pthread_mutex_lock(&p->p_mutex);
  p->p_open = 0;
  if(!p->p_eof) {
    pthread_cond_signal(&p->p_cond);
    pthread_mutex_unlock(&p->p_mutex);
    return 0;
  }
  pipe_destroy(p);
  return 0;
}





#ifndef __APPLE__

static ssize_t
pipe_read2(void *fh, char *buf, size_t size)
{
  return pipe_read(fh, buf, size);
}


static cookie_io_functions_t pipe_read_functions = {
  .read  = pipe_read2,
  .close = pipe_read_close,
};
#endif


fpipe_t *
fpipe(FILE **reader, FILE **writer)
{
  fpipe_t *p = calloc(1, sizeof(fpipe_t));
  pthread_mutex_init(&p->p_mutex, NULL);
  pthread_cond_init(&p->p_cond, NULL);
  p->p_open = 1;
  mbuf_init(&p->p_buffer);

#ifdef __APPLE__
  *reader = funopen(p, pipe_read, NULL, NULL, pipe_read_close);
#else
  *reader = fopencookie(p, "rb", pipe_read_functions);
#endif
  if(*reader != NULL) {
    setvbuf(*reader, NULL, _IOFBF, 65536);
  }

#ifdef __APPLE__
  *writer = funopen(p, NULL, pipe_write, NULL, pipe_write_close);
#else
  *writer = fopencookie(p, "wb", pipe_write_functions);
#endif

  return p;
}

void
fpipe_set_error(fpipe_t *p)
{
  pthread_mutex_lock(&p->p_mutex);
  p->p_err = 1;
  pthread_cond_signal(&p->p_cond);
  pthread_mutex_unlock(&p->p_mutex);
}
