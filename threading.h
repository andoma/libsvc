#pragma once

extern void mutex_unlock_ptr(pthread_mutex_t **p);

#define scoped_lock(x) \
 pthread_mutex_t *scopedmutex__ ## __LINE__ \
 __attribute__((cleanup(mutex_unlock_ptr))) = x; \
 pthread_mutex_lock(x);

static inline int
atomic_add(volatile int *ptr, int incr)
{
  return __sync_fetch_and_add(ptr, incr);
}
