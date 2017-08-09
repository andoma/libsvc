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

#pragma once


typedef struct task_group task_group_t;

typedef void (task_fn_t)(void *opaque);

void task_run(task_fn_t *fn, void *opaque);

task_group_t *task_group_create(void);

task_group_t *task_group_create_with_concurrency(int max_concurrency);

void task_group_destroy(task_group_t *tg);

void task_run_in_group(task_fn_t *fn, void *opaque, task_group_t *tg);

void task_stop(void);

typedef struct task_stats {
  uint32_t num_threads;
  uint32_t idle_threads;
  uint64_t tasks_enqueued;
} task_stats_t;

void task_get_stats(task_stats_t *stats);
