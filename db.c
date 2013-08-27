#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdarg.h>

#include "libsvc/cfg.h"
#include "libsvc/trace.h"

#include "db.h"

static pthread_key_t dbkey;

typedef struct stmt {
  LIST_ENTRY(stmt) link;
  MYSQL_STMT *mysql_stmt;
  char *sql;
} stmt_t;

/**
 *
 */
static MYSQL_STMT *
prep_stmt(MYSQL *m, const char *str)
{
  MYSQL_STMT *ms = mysql_stmt_init(m);
  if(mysql_stmt_prepare(ms, str, strlen(str))) {
    trace(LOG_ERR, "Unable to prepare statement '%s' -- %s",
          str, mysql_error(m));
    return NULL;
  }
  return ms;
}


/**
 *
 */
MYSQL_STMT *
db_stmt_get(conn_t *c, const char *str)
{
  stmt_t *s;
  LIST_FOREACH(s, &c->prep_statements, link) {
    if(!strcmp(s->sql, str))
      break;
  }

  if(s == NULL) {
    s = malloc(sizeof(stmt_t));
    s->sql = strdup(str);
    s->mysql_stmt = prep_stmt(c->m, str);
  } else {
    LIST_REMOVE(s, link);
  }
  LIST_INSERT_HEAD(&c->prep_statements, s, link);
  return s->mysql_stmt;
}


/**
 *
 */
MYSQL_STMT *
db_stmt_prep(const char *sql)
{
  conn_t *c = db_get_conn();
  if(c == NULL)
    return NULL;
  return prep_stmt(c->m, sql);
}


/**
 *
 */
void
db_stmt_cleanup(MYSQL_STMT **ptr)
{
  if(*ptr)
    mysql_stmt_close(*ptr);
}


/**
 *
 */
conn_t *
db_get_conn(void)
{
  conn_t *c = pthread_getspecific(dbkey);
  if(c == NULL) {
    mysql_thread_init();

    MYSQL *m = mysql_init(NULL);

    cfg_root(cfg);

    const char *username = cfg_get_str(cfg, CFG("db", "username"), NULL);
    const char *password = cfg_get_str(cfg, CFG("db", "password"), NULL);
    const char *database = cfg_get_str(cfg, CFG("db", "database"), NULL);

    if(mysql_real_connect(m, "localhost", username,
                          password, database, 0, NULL, 0) != m) {
      trace(LOG_ERR, "Failed to connect: Error: %s", mysql_error(m));
      mysql_close(m);
      return NULL;
    }

    c = calloc(1, sizeof(conn_t));
    c->m = m;
    pthread_setspecific(dbkey, c);
  }
  return c;
}


/**
 *
 */
static void
db_cleanup(void *aux)
{
  conn_t *c = aux;

  stmt_t *s;
  while((s = LIST_FIRST(&c->prep_statements)) != NULL) {
    LIST_REMOVE(s, link);
    mysql_stmt_close(s->mysql_stmt);
    free(s->sql);
    free(s);
  }
  mysql_close(c->m);
  free(c);
}


/**
 *
 */
void
db_init(void)
{
  pthread_key_create(&dbkey, db_cleanup);
}



int
db_stmt_exec(MYSQL_STMT *s, const char *fmt, ...)
{
  if(s == NULL)
    return -1;

  int p, args = strlen(fmt);
  int *x;

  if(mysql_stmt_param_count(s) != args)
    return -1;

  MYSQL_BIND in[args];
  memset(in, 0, sizeof(MYSQL_BIND) * args);
  va_list ap;
  va_start(ap, fmt);

  for(p = 0; *fmt; p++, fmt++) {

    switch(*fmt) {
    case 'i':
      x = alloca(sizeof(int));
      *x = va_arg(ap, int);
      in[p].buffer_type = MYSQL_TYPE_LONG;
      in[p].buffer = (char *)x;
      break;

    case 's':
      in[p].buffer = va_arg(ap, char *);
      if(in[p].buffer != NULL) {
        in[p].buffer_type = MYSQL_TYPE_STRING;
        in[p].buffer_length = strlen(in[p].buffer);
      } else {
        in[p].buffer_type = MYSQL_TYPE_NULL;
      }
      break;

    case 'b':
      in[p].buffer = va_arg(ap, char *);
      in[p].buffer_length = va_arg(ap, int);
      in[p].buffer_type = MYSQL_TYPE_STRING;
      break;

    default:
      abort();
    }
  }

  if(mysql_stmt_bind_param(s, in)) {
    trace(LOG_ERR, "Failed to bind parameters to prepared statement %s -- %s",
          mysql_stmt_sqlstate(s), mysql_stmt_error(s));
    return -1;
  }

  if(mysql_stmt_execute(s)) {
    trace(LOG_ERR, "Failed to execute prepared statement %s -- %s",
          mysql_stmt_sqlstate(s), mysql_stmt_error(s));
    return -1;
  }
  return 0;
}


/**
 *
 */
int
db_stream_row(int flags, MYSQL_STMT *s, ...)
{
  int fields = mysql_stmt_field_count(s);

  MYSQL_BIND out[fields];
  unsigned long lens[fields];
  MYSQL_TIME times[fields];
  time_t *tptr[fields];
  int p = 0, i;
  struct tm tm = {};

  memset(out, 0, sizeof(MYSQL_BIND) * fields);
  memset(lens, 0, sizeof(unsigned long) * fields);

  va_list ap;
  va_start(ap, s);

  while(p < fields) {
    int type = va_arg(ap, int);
    switch(type) {
    case DB_RESULT_TAG_STR:
      out[p].buffer_type = MYSQL_TYPE_STRING;
      out[p].buffer = va_arg(ap, char *);
      out[p].buffer_length = va_arg(ap, int) - 1;
      out[p].length = &lens[p];
      break;

    case DB_RESULT_TAG_INT:
      out[p].buffer_type = MYSQL_TYPE_LONG;
      out[p].buffer = va_arg(ap, int *);
      out[p].buffer_length = sizeof(int);
      out[p].length = &lens[p];
      break;

    case DB_RESULT_TAG_TIME:
      out[p].buffer_type = MYSQL_TYPE_TIMESTAMP;
      out[p].buffer = (char *)&times[p];
      out[p].buffer_length = sizeof(MYSQL_TIME);

      tptr[p] = va_arg(ap, time_t *);
      break;

    default:
      abort();
    }
    p++;
  }

  if(fields != p) {
    trace(LOG_ERR, "Bind invalid number of arguments for %s -- %d vs %d",
          mysql_stmt_sqlstate(s), mysql_stmt_field_count(s), p);
    return -1;
  }

  if(mysql_stmt_bind_result(s, out)) {
    trace(LOG_ERR, "Bind failed for statement %s -- %s",
          mysql_stmt_sqlstate(s), mysql_stmt_error(s));
    return -1;
  }

  if(flags & DB_STORE_RESULT)
    mysql_stmt_store_result(s);

  switch(mysql_stmt_fetch(s)) {
  case 0:
    for(i = 0; i < p; i++) {
      switch(out[i].buffer_type) {
      case MYSQL_TYPE_STRING:
        ((char *)out[i].buffer)[lens[i]] = 0;
        break;
      case MYSQL_TYPE_TIMESTAMP:
        if(times[i].year == 0) {
          *tptr[i] = 0;
          break;
        }

        tm.tm_sec  = times[i].second;
        tm.tm_min  = times[i].minute;
        tm.tm_hour = times[i].hour;
        tm.tm_mday = times[i].day;
        tm.tm_mon  = times[i].month - 1;
        tm.tm_year = times[i].year - 1900;
        // This is crap
        tm.tm_isdst = -1;
        *tptr[i] = mktime(&tm);
        break;

      default:
        break;
      }
    }
    return 0;

  case MYSQL_NO_DATA:
    return 1;

  case MYSQL_DATA_TRUNCATED:
    trace(LOG_ERR, "Data truncated for %s",
          mysql_stmt_sqlstate(s));
    return -1;

  default:
    trace(LOG_ERR, "Bind failed for statement %s -- %s",
          mysql_stmt_sqlstate(s), mysql_stmt_error(s));
    return -1;
  }
}


/**
 *
 */
int
db_begin(conn_t *c)
{
  int r = mysql_query(c->m, "START TRANSACTION");
  if(!r)
    return 0;
  trace(LOG_ERR, "Unable to start transaction -- %s",
        mysql_error(c->m));
  return -1;
}


/**
 *
 */
int
db_commit(conn_t *c)
{
  if(mysql_commit(c->m))
    trace(LOG_ERR, "Unable to commit transaction -- %s",
          mysql_error(c->m));
  return 0;
}


/**
 *
 */
int
db_rollback(conn_t *c)
{
  if(mysql_rollback(c->m))
    trace(LOG_ERR, "Unable to rollback transaction -- %s",
          mysql_error(c->m));
  return 0;
}
