#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <dirent.h>

#include "libsvc/htsmsg_json.h"
#include "libsvc/misc.h"
#include "libsvc/trace.h"
#include "libsvc/threading.h"

#include "cfg.h"

static pthread_mutex_t cfg_mutex = PTHREAD_MUTEX_INITIALIZER;
static cfg_t *cfgroot;



/**
 *
 */
cfg_t *
cfg_get_root(void)
{
  pthread_mutex_lock(&cfg_mutex);
  cfg_t *c = cfgroot;
  htsmsg_retain(c);
  pthread_mutex_unlock(&cfg_mutex);
  return c;
}

void
cfg_releasep(cfg_t **p)
{
  if(*p)
    htsmsg_release(*p);
}


/**
 *
 */
int
cfg_load(const char *filename, const char *defconf)
{
  int err;
  static char *lastfilename;

  if(filename == NULL) {
    filename = lastfilename;

  } else {

    free(lastfilename);
    lastfilename = strdup(filename);
  }

  if(filename == NULL)
    filename = defconf;

  trace(LOG_NOTICE, "About to load config form %s", filename);

  char *cfgtxt = readfile(filename, &err, NULL);
  if(cfgtxt == NULL) {
    trace(LOG_ERR, "Unable to read file %s -- %s", filename, strerror(err));
    trace(LOG_ERR, "Config not updated");
    return -1;
  }

  char errbuf[256];
  htsmsg_t *m = htsmsg_json_deserialize(cfgtxt, errbuf, sizeof(errbuf));
  free(cfgtxt);
  if(m == NULL) {
    trace(LOG_ERR, "Unable to parse file %s -- %s", filename, errbuf);
    trace(LOG_ERR, "Config not updated");
    return -1;
  }

  pthread_mutex_lock(&cfg_mutex);
  if(cfgroot != NULL)
    htsmsg_release(cfgroot);

  cfgroot = m;
  htsmsg_retain(m);
  pthread_mutex_unlock(&cfg_mutex);
  trace(LOG_NOTICE, "Config updated");
  return 0;
}


/**
 *
 */
static htsmsg_field_t *
field_from_vec(cfg_t *m, const char **vec)
{
  htsmsg_field_t *f = NULL;
  while(*vec) {
    f = htsmsg_field_find(m, vec[0]);
    if(f == NULL)
      return NULL;
    if(vec[1] == NULL)
      return f;
    if(f->hmf_type != HMF_MAP && f->hmf_type != HMF_LIST)
      return NULL;
    m = &f->hmf_msg;
    vec++;
  }
  return NULL;
}


/**
 *
 */
const char *
cfg_get_str(cfg_t *c, const char **vec, const char *def)
{
  htsmsg_field_t *f = field_from_vec(c, vec);
  if(f == NULL)
    return def;

  return htsmsg_field_get_string(f) ?: def;
}


/**
 *
 */
int64_t
cfg_get_s64(cfg_t *c, const char **path, int64_t def)
{
  htsmsg_field_t *f = field_from_vec(c, path);
  if(f == NULL)
    return def;

  switch(f->hmf_type) {
  default:
    return def;
  case HMF_STR:
    return strtoll(f->hmf_str, NULL, 0);
  case HMF_S64:
    return f->hmf_s64;
  }
}


/**
 *
 */
int
cfg_get_int(cfg_t *c, const char **path, int def)
{
  int64_t s64 = cfg_get_s64(c, path, def);

  if(s64 < -0x80000000LL || s64 > 0x7fffffffLL)
    return def;
  return s64;
}


#if 0
/**
 *
 */
cfg_t *
cfg_get_project(cfg_t *c, const char *id)
{
  htsmsg_t *m = htsmsg_get_map(c, "projects");
  m =  m ? htsmsg_get_map(m, id) : NULL;
  if(m == NULL)
    trace(LOG_ERR, "%s: No config for project", id);
  return m;
}
#endif


/**
 *
 */
cfg_t *
cfg_get_map(cfg_t *c, const char *id)
{
  return htsmsg_get_map(c, id);
}


/**
 *
 */
cfg_t *
cfg_get_list(cfg_t *c, const char *id)
{
  return htsmsg_get_list(c, id);
}


/**
 *
 */
int
cfg_list_length(cfg_t *c)
{
  htsmsg_field_t *f;
  int r = 0;
  HTSMSG_FOREACH(f, c) {
    if(f->hmf_type == HMF_COMMENT)
      continue;
    r++;
  }
  return r;
}

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
