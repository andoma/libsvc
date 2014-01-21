#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

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
static void __attribute__((constructor))
talloc_init(void)
{
  pthread_key_create(&talloc_key, talloc_thread_cleanup);
}


