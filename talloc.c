#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <stdarg.h>

#include "talloc.h"

typedef struct talloc_item {
  struct talloc_item *next;
} talloc_item_t;

//static talloc_item_t __thread *talloc_queue;
static pthread_key_t talloc_key;



/**
 *
 */
static talloc_item_t **
talloc_getq(void)
{
  talloc_item_t **q = pthread_getspecific(talloc_key);
  if(q)
    return q;

  q = calloc(1, sizeof(talloc_item_t *));
  pthread_setspecific(talloc_key, q);
  return q;
}



/**
 *
 */
static void
talloc_free_items(talloc_item_t **q)
{
  talloc_item_t *p, *next;
  for(p = *q; p != NULL; p = next) {
    next = p->next;
    free(p);
  }
  *q = NULL;
}


/**
 *
 */
static void
talloc_thread_cleanup(void *aux)
{
  talloc_free_items(aux);
  free(aux);
}


/**
 *
 */
void
talloc_cleanup(void)
{
  talloc_item_t **q = pthread_getspecific(talloc_key);
  if(q != NULL)
    talloc_free_items(q);
}


/**
 *
 */
static void
talloc_insert(talloc_item_t *t)
{
  talloc_item_t **q = talloc_getq();
  t->next = *q;
  *q = t;
}


/**
 *
 */
void *
talloc_malloc(size_t s)
{
  talloc_item_t *t = malloc(s + sizeof(talloc_item_t));
  talloc_insert(t);
  return t + 1;
}


/**
 *
 */
void *
talloc_zalloc(size_t s)
{
  talloc_item_t *t = calloc(1, s + sizeof(talloc_item_t));
  talloc_insert(t);
  return t + 1;
}


/**
 *
 */
char *
tstrdup(const char *str)
{
  size_t len = strlen(str);
  char *r = talloc_malloc(len + 1);
  memcpy(r, str, len);
  r[len] = 0;
  return r;
}


/**
 *
 */
char *
tsprintf(const char *fmt, ...)
{
  char buf[100];
  va_list ap;
  int n;

  va_start(ap, fmt);
  n = vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);

  if(n < 0)
    abort();

  if(n < sizeof(buf))
    return tstrdup(buf);

  char *b = talloc_malloc(n + 1);

  va_start(ap, fmt);
  vsnprintf(b, n + 1, fmt, ap);
  va_end(ap);
  return b;
}


/**
 *
 */
static void __attribute__((constructor))
talloc_init(void)
{
  pthread_key_create(&talloc_key, talloc_thread_cleanup);
}


