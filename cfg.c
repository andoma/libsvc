/******************************************************************************
* Copyright (C) 2013 - 2014 Andreas Öman
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
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <dirent.h>

#include "misc.h"
#include "trace.h"
#include "ntv.h"
#include "cfg.h"
#include "cmd.h"

LIST_HEAD(reload_cb_list, reload_cb);
static struct reload_cb_list reload_cbs;
static pthread_mutex_t cfg_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t reload_mutex = PTHREAD_MUTEX_INITIALIZER;
static cfg_t *cfgroot;


typedef struct reload_cb {
  void (*fn)(void);
  LIST_ENTRY(reload_cb) link;
} reload_cb_t;

/**
 *
 */
void
cfg_add_reload_cb(void (*fn)(void))
{
  reload_cb_t *rc = malloc(sizeof(reload_cb_t));
  rc->fn = fn;
  pthread_mutex_lock(&reload_mutex);
  LIST_INSERT_HEAD(&reload_cbs, rc, link);
  pthread_mutex_unlock(&reload_mutex);
}

/**
 *
 */
static void
cfg_call_reload_callbacks(void)
{
  reload_cb_t *rc;
  pthread_mutex_lock(&reload_mutex);
  LIST_FOREACH(rc, &reload_cbs, link)
    rc->fn();
  pthread_mutex_unlock(&reload_mutex);
}


/**
 *
 */
cfg_t *
cfg_get_root(void)
{
  pthread_mutex_lock(&cfg_mutex);
  cfg_t *c = ntv_retain(cfgroot);
  pthread_mutex_unlock(&cfg_mutex);
  return c;
}

void
cfg_releasep(cfg_t **p)
{
  if(*p) {
    pthread_mutex_lock(&cfg_mutex);
    ntv_release(*p);
    pthread_mutex_unlock(&cfg_mutex);
  }
}


int
cfg_load_str(const char *json, char *errbuf, size_t errlen)
{
  ntv_t *msg = ntv_json_deserialize(json, errbuf, errlen);
  if(msg == NULL)
    return -1;
  pthread_mutex_lock(&cfg_mutex);
  if(cfgroot != NULL)
    ntv_release(cfgroot);

  cfgroot = msg;
  pthread_mutex_unlock(&cfg_mutex);
  trace(LOG_NOTICE, "Config updated");
  cfg_call_reload_callbacks();
  return 0;
}

/**
 *
 */
int
cfg_load(const char *filename, char *errbuf, size_t errlen)
{
  static char *lastfilename;

  pthread_mutex_lock(&cfg_mutex);

  if(filename == NULL) {
    if(lastfilename == NULL) {
      snprintf(errbuf, errlen, "No path for config");
      trace(LOG_ERR, "No path for config");
      pthread_mutex_unlock(&cfg_mutex);
      return -1;
    }
    filename = mystrdupa(lastfilename);
  } else {
    free(lastfilename);
    lastfilename = strdup(filename);
  }

  pthread_mutex_unlock(&cfg_mutex);

  trace(LOG_NOTICE, "About to load config form %s", filename);

  scoped_char *cfgtxt = readfile(filename, NULL);
  if(cfgtxt == NULL) {
    const char *errstr = strerror(errno);
    snprintf(errbuf, errlen, "Unable to read file %s -- %s", filename, errstr);
    trace(LOG_ERR, "Unable to read file %s -- %s", filename, errstr);
    trace(LOG_ERR, "Config not updated");
    return -1;
  }

  char errbuf2[256];
  int r = cfg_load_str(cfgtxt, errbuf2, sizeof(errbuf2));
  if(r) {
    snprintf(errbuf, errlen, "Unable to parse file %s -- %s", filename, errbuf2);
    trace(LOG_ERR, "Unable to parse file %s -- %s", filename, errbuf2);
    trace(LOG_ERR, "Config not updated");
    return -1;
  }
  return 0;
}



/**
 *
 */
const char *
cfg_get_str(const ntv_t *msg, const char **vec, const char *def)
{
  return ntv_get_str(ntv_field_from_path(msg, vec), NULL) ?: def;
}


/**
 *
 */
int64_t
cfg_get_s64(const ntv_t *msg, const char **path, int64_t def)
{
  return ntv_get_int64(ntv_field_from_path(msg, path), NULL, def);
}


/**
 *
 */
double
cfg_get_dbl(const ntv_t *msg, const char **path, double def)
{
  return ntv_get_double(ntv_field_from_path(msg, path), NULL, def);
}


/**
 *
 */
int
cfg_get_int(const ntv_t *msg, const char **path, int def)
{
  return ntv_get_int(ntv_field_from_path(msg, path), NULL, def);
}

#if 0
/**
 *
 */
cfg_t *
cfg_find_map(cfg_t *c, const char *key, const char *value)
{
  if(c == NULL)
    return NULL;

  htsmsg_field_t *f;
  HTSMSG_FOREACH(f, c) {
    htsmsg_t *m = htsmsg_get_map_by_field(f);
    if(m == NULL)
      continue;

    const char *s = htsmsg_get_str(m, key);
    if(s != NULL && !strcmp(value, s))
      return m;
  }
  return NULL;
}
#endif


static int
reload_configuration(const char *user,
                     int argc, const char **argv, int *intv,
                     void (*msg)(void *opaque, const char *fmt, ...),
                     void *opaque)
{
  char errbuf[512];
  if(cfg_load(NULL, errbuf, sizeof(errbuf))) {
    msg(opaque, "Unable to load configuration -- %s", errbuf);
    return 1;
  } else {
    msg(opaque, "Config reloaded OK");
    return 0;
  }
}

CMD(reload_configuration,
    CMD_LITERAL("reload"),
    CMD_LITERAL("configuration"));
