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

#include <stdlib.h>
#include <pthread.h>
#include <sys/queue.h>
#include <assert.h>
#include <errno.h>
#include "task.h"
#include "atomic.h"
#include "talloc.h"

#define MAX_TASK_THREADS 64
#define MAX_IDLE_TASK_THREADS 4


LIST_HEAD(task_thread_list, task_thread);
TAILQ_HEAD(task_queue, task);
TAILQ_HEAD(task_group_queue, task_group);

typedef struct task_thread {
  LIST_ENTRY(task_thread) link;
  pthread_t tid;
} task_thread_t;

struct task_group {
  atomic_t tg_refcount;
  struct task_queue tg_tasks;
  TAILQ_ENTRY(task_group) tg_link;
  int tg_max_concurrency;
  int tg_num_processing;
};


typedef struct task {
  TAILQ_ENTRY(task) t_link;
  task_fn_t *t_fn;
  void *t_opaque;
  task_group_t *t_group;
} task_t;


static struct task_queue tasks = TAILQ_HEAD_INITIALIZER(tasks);
static struct task_group_queue task_groups =TAILQ_HEAD_INITIALIZER(task_groups);
static atomic_t num_task_threads;
static unsigned int num_task_threads_avail;
static pthread_mutex_t task_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t task_cond = PTHREAD_COND_INITIALIZER;
static int task_sys_running = 1;
static struct task_thread_list task_threads;
static uint64_t tasks_enqueued;

/**
 *
 */
static void
task_group_release(task_group_t *tg)
{
  if(atomic_dec(&tg->tg_refcount))
    return;
  assert(TAILQ_FIRST(&tg->tg_tasks) == NULL);
  assert(tg->tg_num_processing == 0);
  free(tg);
}


/**
 *
 */
static void *
task_thread(void *aux)
{
  task_thread_t *tt = aux;
  task_t *t;
  task_group_t *tg;

  pthread_mutex_lock(&task_mutex);
  while(task_sys_running) {
    t = TAILQ_FIRST(&tasks);
    tg = TAILQ_FIRST(&task_groups);

    if(t == NULL && tg == NULL) {
      if(num_task_threads_avail >= MAX_IDLE_TASK_THREADS) {

        struct timespec timeout;

        timeout.tv_sec = time(NULL) + 5;
        timeout.tv_nsec = 0;

        num_task_threads_avail++;
        int r = pthread_cond_timedwait(&task_cond, &task_mutex, &timeout);
        num_task_threads_avail--;

        if(r == ETIMEDOUT) {
          break;
        }

      } else {
        num_task_threads_avail++;
        pthread_cond_wait(&task_cond, &task_mutex);
        num_task_threads_avail--;
      }
      continue;
    }

    if(t != NULL) {
      TAILQ_REMOVE(&tasks, t, t_link);
      pthread_mutex_unlock(&task_mutex);
      t->t_fn(t->t_opaque);
      free(t);
      talloc_cleanup();
      pthread_mutex_lock(&task_mutex);
      // Released lock, must recheck for task groups
      tg = TAILQ_FIRST(&task_groups);
    }

    if(tg != NULL) {
      t = TAILQ_FIRST(&tg->tg_tasks);
      TAILQ_REMOVE(&tg->tg_tasks, t, t_link);

      tg->tg_num_processing++;

      if(TAILQ_FIRST(&tg->tg_tasks) == NULL ||
         tg->tg_num_processing == tg->tg_max_concurrency) {
        // Remove if we are at max concurrency or there no more tasks to do
        TAILQ_REMOVE(&task_groups, tg, tg_link);
      }

      pthread_mutex_unlock(&task_mutex);
      t->t_fn(t->t_opaque);
      pthread_mutex_lock(&task_mutex);
      free(t);

      assert(tg->tg_num_processing > 0);
      tg->tg_num_processing--;
      if(TAILQ_FIRST(&tg->tg_tasks) != NULL &&
         tg->tg_num_processing == tg->tg_max_concurrency - 1) {
        TAILQ_INSERT_TAIL(&task_groups, tg, tg_link);
      }

      // Decrease refcount owned by task
      task_group_release(tg);
    }
  }

  atomic_add(&num_task_threads, -1);
  if(task_sys_running) {
    pthread_detach(tt->tid);
    LIST_REMOVE(tt, link);
    free(tt);
  }
  pthread_mutex_unlock(&task_mutex);
  return NULL;
}


/**
 *
 */
static void
task_launch_thread(void)
{
  assert(task_sys_running != 0);
  atomic_add(&num_task_threads, 1);

  task_thread_t *tt = calloc(1, sizeof(task_thread_t));
  LIST_INSERT_HEAD(&task_threads, tt, link);
  pthread_create(&tt->tid, NULL, task_thread, tt);
}


/**
 *
 */
static void
task_schedule()
{
  if(num_task_threads_avail > 0) {
    pthread_cond_signal(&task_cond);
  } else {
    if(atomic_get(&num_task_threads) < MAX_TASK_THREADS) {
      task_launch_thread();
    }
  }
}


/**
 *
 */
void
task_run(task_fn_t *fn, void *opaque)
{
  task_t *t = calloc(1, sizeof(task_t));
  t->t_fn = fn;
  t->t_opaque = opaque;
  pthread_mutex_lock(&task_mutex);
  TAILQ_INSERT_TAIL(&tasks, t, t_link);
  task_schedule();
  tasks_enqueued++;
  pthread_mutex_unlock(&task_mutex);
}



/**
 *
 */
task_group_t *
task_group_create_with_concurrency(int max_concurrency)
{
  task_group_t *tg = calloc(1, sizeof(task_group_t));
  atomic_set(&tg->tg_refcount, 1);
  tg->tg_max_concurrency = max_concurrency;
  TAILQ_INIT(&tg->tg_tasks);
  return tg;
}


/**
 *
 */
task_group_t *
task_group_create(void)
{
  return task_group_create_with_concurrency(1);
}




/**
 *
 */
void
task_group_destroy(task_group_t *tg)
{
  task_group_release(tg);
}


/**
 *
 */
void
task_run_in_group(task_fn_t *fn, void *opaque, task_group_t *tg)
{
  task_t *t = calloc(1, sizeof(task_t));
  t->t_fn = fn;
  t->t_opaque = opaque;
  pthread_mutex_lock(&task_mutex);

  tasks_enqueued++;

  if(task_sys_running) {
    t->t_group = tg;
    atomic_inc(&tg->tg_refcount);

    if(TAILQ_FIRST(&tg->tg_tasks) == NULL &&
       tg->tg_num_processing < tg->tg_max_concurrency) {
      TAILQ_INSERT_TAIL(&task_groups, tg, tg_link);
    }
    TAILQ_INSERT_TAIL(&tg->tg_tasks, t, t_link);
    task_schedule();
  } else {
    TAILQ_INSERT_TAIL(&tasks, t, t_link);
  }
  pthread_mutex_unlock(&task_mutex);
}


/**
 *
 */
void
task_stop(void)
{
  task_thread_t *tt;

  pthread_mutex_lock(&task_mutex);
  task_sys_running = 0;
  pthread_cond_broadcast(&task_cond);

  while((tt = LIST_FIRST(&task_threads)) != NULL) {
    LIST_REMOVE(tt, link);
    pthread_mutex_unlock(&task_mutex);
    pthread_join(tt->tid, NULL);
    pthread_mutex_lock(&task_mutex);
    free(tt);
  }
  pthread_mutex_unlock(&task_mutex);
}


/**
 *
 */
void
task_get_stats(task_stats_t *stats)
{
  stats->num_threads = atomic_get(&num_task_threads);

  pthread_mutex_lock(&task_mutex);

  stats->idle_threads = num_task_threads_avail;
  stats->tasks_enqueued = tasks_enqueued;

  pthread_mutex_unlock(&task_mutex);
}


int
task_system_overload(void)
{
  const int limit = MAX_TASK_THREADS * 3 / 4;
  return atomic_get(&num_task_threads) > limit;
}
