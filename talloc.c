#include <stdlib.h>
#include <pthread.h>

#include "talloc.h"

typedef struct talloc_item {
  struct talloc_item *next;
} talloc_item_t;

static talloc_item_t __thread *talloc_queue;
static pthread_key_t talloc_key;


/**
 *
 */
void
talloc_cleanup(void)
{
  talloc_item_t *p, *next;
  for(p = talloc_queue; p != NULL; p = next) {
    next = p->next;
    free(p);
  }
  talloc_queue = NULL;
}


/**
 *
 */
static void
talloc_thread_cleanup(void *aux)
{
  talloc_cleanup();
}


/**
 *
 */
void *
talloc_malloc(size_t s)
{
  talloc_item_t *t = malloc(s + sizeof(talloc_item_t));
  t->next = talloc_queue;
  talloc_queue = t;
  return t + 1;
}


/**
 *
 */
void *
talloc_zalloc(size_t s)
{
  talloc_item_t *t = calloc(1, s + sizeof(talloc_item_t));
  t->next = talloc_queue;
  talloc_queue = t;
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


