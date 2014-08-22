#pragma once

typedef void (task_fn_t)(void *opaque);

void task_run(task_fn_t *fn, void *opaque);

