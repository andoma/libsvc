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
#include "task.h"
#include "atomic.h"
#include "talloc.h"

#define MAX_TASK_THREADS 64
#define MAX_IDLE_TASK_THREADS 4


TAILQ_HEAD(task_queue, task);
TAILQ_HEAD(task_group_queue, task_group);

struct task_group {
  atomic_t tg_refcount;
  struct task_queue tg_tasks;
  TAILQ_ENTRY(task_group) tg_link;
};


typedef struct task {
  TAILQ_ENTRY(task) t_link;
  task_fn_t *t_fn;
  void *t_opaque;
  task_group_t *t_group;
} task_t;


static struct task_queue tasks = TAILQ_HEAD_INITIALIZER(tasks);
static struct task_group_queue task_groups =TAILQ_HEAD_INITIALIZER(task_groups);
static unsigned int num_task_threads;
static unsigned int num_task_threads_avail;
static pthread_mutex_t task_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t task_cond = PTHREAD_COND_INITIALIZER;
static pthread_cond_t task_end_cond = PTHREAD_COND_INITIALIZER;
static int task_sys_running = 1;

/**
 *
 */
static void
task_group_release(task_group_t *tg)
{
  if(atomic_dec(&tg->tg_refcount))
    return;
  assert(TAILQ_FIRST(&tg->tg_tasks) == NULL);
  free(tg);
}


/**
 *
 */
static void *
task_thread(void *aux)
{
  task_t *t;
  task_group_t *tg;

  pthread_mutex_lock(&task_mutex);
  while(task_sys_running) {
    t = TAILQ_FIRST(&tasks);
    tg = TAILQ_FIRST(&task_groups);

    if(t == NULL && tg == NULL) {
      if(num_task_threads_avail >= MAX_IDLE_TASK_THREADS)
        break;

      num_task_threads_avail++;
      pthread_cond_wait(&task_cond, &task_mutex);
      num_task_threads_avail--;
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
      // Remove task group while processing as we don't want anyone
      // else to dispatch from this group
      TAILQ_REMOVE(&task_groups, tg, tg_link);

      t = TAILQ_FIRST(&tg->tg_tasks);
      pthread_mutex_unlock(&task_mutex);
      t->t_fn(t->t_opaque);
      pthread_mutex_lock(&task_mutex);

      // Note that we remove _after_ execution because we don't want
      // any newly inserted task in this group to cause the group
      // to activate (ie, get inserted in task_groups)
      TAILQ_REMOVE(&tg->tg_tasks, t, t_link);
      free(t);

      if(TAILQ_FIRST(&tg->tg_tasks) != NULL) {
        // Still more tasks to work on in this group
        // Reinsert group at tail to maintain fairness between groups
        TAILQ_INSERT_TAIL(&task_groups, tg, tg_link);
      }

      // Decrease refcount owned by task
      task_group_release(tg);
    }
  }

  num_task_threads--;
  pthread_cond_signal(&task_end_cond);
  pthread_mutex_unlock(&task_mutex);
  return NULL;
}


/**
 *
 */
static void
task_launch_thread(void)
{
  num_task_threads++;

  pthread_t id;
  pthread_attr_t attr;
  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
  pthread_create(&id, &attr, task_thread, NULL);
  pthread_attr_destroy(&attr);
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
    if(num_task_threads < MAX_TASK_THREADS) {
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
  pthread_mutex_unlock(&task_mutex);
}



/**
 *
 */
task_group_t *
task_group_create(void)
{
  task_group_t *tg = calloc(1, sizeof(task_group_t));
  atomic_set(&tg->tg_refcount, 1);
  TAILQ_INIT(&tg->tg_tasks);
  return tg;
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

  if(task_sys_running) {
    t->t_group = tg;
    atomic_inc(&tg->tg_refcount);

    if(TAILQ_FIRST(&tg->tg_tasks) == NULL)
      TAILQ_INSERT_TAIL(&task_groups, tg, tg_link);

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
  pthread_mutex_lock(&task_mutex);
  task_sys_running = 0;
  pthread_cond_broadcast(&task_cond);

  while(num_task_threads) {
    pthread_cond_wait(&task_end_cond, &task_mutex);
  }

  pthread_mutex_unlock(&task_mutex);
}
