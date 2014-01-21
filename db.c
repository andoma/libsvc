#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdarg.h>

#include "cfg.h"
#include "trace.h"
#include "filebundle.h"

#include "db.h"

#include <mysql.h>
#include <mysqld_error.h>
#include <errmsg.h>

static pthread_key_t dbkey;

typedef struct db_stmt {
  LIST_ENTRY(db_stmt) link;
  MYSQL_STMT *mysql_stmt;
  char *sql;
  struct db_conn *c;
} db_stmt_t;

LIST_HEAD(db_stmt_list, db_stmt);

struct db_conn {
  MYSQL *m;
  struct db_stmt_list prep_statements;
};


static int db_reconnect(db_conn_t *c) __attribute__ ((warn_unused_result));

static void db_cleanup(void *aux);

/**
 *
 */
static MYSQL_STMT *
prep_stmt(db_conn_t *c, const char *str)
{
  while(1) {
    MYSQL_STMT *ms = mysql_stmt_init(c->m);
    if(!mysql_stmt_prepare(ms, str, strlen(str)))
      return ms;

    switch(mysql_errno(c->m)) {
    case CR_SERVER_GONE_ERROR:
    case CR_SERVER_LOST:
      mysql_stmt_close(ms);
      if(db_reconnect(c))
        return NULL;
      continue;
    default:
      trace(LOG_ERR, "Unable to prepare statement '%s' -- %s",
            str, mysql_error(c->m));
      mysql_stmt_close(ms);
      return NULL;
    }
  }
}


/**
 *
 */
db_stmt_t *
db_stmt_get(db_conn_t *c, const char *str)
{
  db_stmt_t *s;
  LIST_FOREACH(s, &c->prep_statements, link) {
    if(!strcmp(s->sql, str))
      break;
  }

  if(s == NULL) {
    s = malloc(sizeof(db_stmt_t));
    s->mysql_stmt = prep_stmt(c, str);
    s->c = c;
    if(s->mysql_stmt == NULL) {
      free(s);
      return NULL;
    }
    s->sql = strdup(str);
  } else {
    LIST_REMOVE(s, link);
    mysql_stmt_reset(s->mysql_stmt);
  }
  LIST_INSERT_HEAD(&c->prep_statements, s, link);
  return s;
}


/**
 *
 */
static void
db_stmt_kill(db_stmt_t *s)
{
  mysql_stmt_close(s->mysql_stmt);
  free(s->sql);
  LIST_REMOVE(s, link);
  free(s);
}


/**
 *
 */
db_stmt_t *
db_stmt_prep(const char *sql)
{
  db_conn_t *c = db_get_conn();
  if(c == NULL)
    return NULL;
  return db_stmt_get(c, sql);
}


/**
 *
 */
void
db_stmt_cleanup(db_stmt_t **ptr)
{
  if(*ptr)
    db_stmt_kill(*ptr);
}


/**
 *
 */
static MYSQL *
db_connect(void)
{
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

  const char *q = "SET NAMES utf8";
  MYSQL_STMT *s = mysql_stmt_init(m);

  if(mysql_stmt_prepare(s, q, strlen(q))) {
    trace(LOG_ERR, "Unable to prep UTF-8 stmt on db connection");
    mysql_close(m);
    return NULL;
  }

  if(mysql_stmt_execute(s)) {
    trace(LOG_ERR, "Unable to enable UTF-8 on db connection");
    mysql_close(m);
    return NULL;
  }
  mysql_stmt_close(s);
  return m;
}

/**
 *
 */
static int
db_reconnect(db_conn_t *c)
{
  db_stmt_t *s;
 again:
  LIST_FOREACH(s, &c->prep_statements, link) {
    mysql_stmt_close(s->mysql_stmt);
    s->mysql_stmt = NULL;
  }
  mysql_close(c->m);
  c->m = NULL;

  trace(LOG_INFO, "Mysql: Reconnecting");

  for(int i = 0; i < 10; i++) {
    c->m = db_connect();

    if(c->m != NULL)
      break;
    int timo = 1 + i * 2;
    trace(LOG_INFO, "Mysql: Reconnect failed, retrying in %d seconds", timo);
    sleep(timo);
  }

  if(c->m == NULL) {
    trace(LOG_ALERT, "Unable to reconnect to mysql -- stuff may fail now");
    db_cleanup(c);
    return -1;
  }

  LIST_FOREACH(s, &c->prep_statements, link) {
    s->mysql_stmt = mysql_stmt_init(c->m);
    if(!mysql_stmt_prepare(s->mysql_stmt, s->sql, strlen(s->sql)))
      continue;

    switch(mysql_errno(c->m)) {
    case CR_SERVER_GONE_ERROR:
    case CR_SERVER_LOST:
      mysql_stmt_close(s->mysql_stmt);
      s->mysql_stmt = NULL;
      goto again;
    default:
      trace(LOG_ERR, "Unable to prepare statement '%s' -- %s",
            s->sql, mysql_error(c->m));
      mysql_stmt_close(s->mysql_stmt);
      s->mysql_stmt = NULL;
      break;
    }
  }
  return 0;
}


/**
 *
 */
db_conn_t *
db_get_conn(void)
{
  db_conn_t *c = pthread_getspecific(dbkey);
  if(c == NULL) {
    //    mysql_thread_init();

    MYSQL *m = db_connect();

    c = calloc(1, sizeof(db_conn_t));
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
  db_conn_t *c = aux;
  db_stmt_t *s;
  while((s = LIST_FIRST(&c->prep_statements)) != NULL) {
    LIST_REMOVE(s, link);
    if(s->mysql_stmt != NULL)
      mysql_stmt_close(s->mysql_stmt);
    free(s->sql);
    free(s);
  }
  if(c->m != NULL)
    mysql_close(c->m);
  free(c);
  mysql_thread_end();
}


/**
 *
 */
void
db_init(void)
{
  mysql_library_init(0, NULL, NULL);
  pthread_key_create(&dbkey, db_cleanup);
}



/**
 *
 */
static int
db_stmt_bind_exec(db_stmt_t *stmt, MYSQL_BIND *in,
                 const db_args_t *argv, int argc)
{
  MYSQL_STMT *s = stmt->mysql_stmt;
  int err;
  unsigned long *lengths = malloc(sizeof(unsigned long) * argc);

  for(int p = 0; p < argc; p++) {
    lengths[p] = in[p].buffer_length;
    in[p].length = &lengths[p];
  }

  err = mysql_stmt_bind_param(s, in);
  if(err) {
    trace(LOG_ERR, "Failed to bind parameters to prepared statement %s -- %s",
          stmt->sql, mysql_stmt_error(s));
    free(lengths);
    return mysql_stmt_errno(s);
  }

  err = mysql_stmt_execute(s);
  if(err) {
    trace(LOG_ERR, "Failed to execute prepared statement %s -- %s",
          stmt->sql, mysql_stmt_error(s));
    free(lengths);
    return mysql_stmt_errno(s);
  }
  free(lengths);
  return 0;
}


/**
 *
 */
static int
db_stmt_exec_try(db_stmt_t *stmt, MYSQL_BIND *in,
                 const db_args_t *argv, int argc)
{
  while(1) {
    if(mysql_stmt_param_count(stmt->mysql_stmt) != argc)
      return DB_ERR_OTHER;

    int err = db_stmt_bind_exec(stmt, in, argv, argc);
    switch(err) {
    case 0:
      return DB_ERR_OK;
    case CR_SERVER_GONE_ERROR:
    case CR_SERVER_LOST:
      if(db_reconnect(stmt->c))
        return DB_ERR_OTHER;
      break;
    case ER_LOCK_DEADLOCK:
      return DB_ERR_DEADLOCK;
    default:
      trace(LOG_ERR, "Unable to exec statement '%s' -- %s",
            stmt->sql, mysql_error(stmt->c->m));
      return DB_ERR_OTHER;
    }
  }
}


/**
 *
 */
db_err_t
db_stmt_execa(db_stmt_t *stmt, int argc, const db_args_t *argv)
{
  if(stmt == NULL)
    return DB_ERR_OTHER;

  MYSQL_BIND in[argc];
  memset(in, 0, sizeof(MYSQL_BIND) * argc);

  for(int p = 0; p < argc; p++) {
    switch(argv[p].type) {
    case 'i':
      in[p].buffer_type = MYSQL_TYPE_LONG;
      in[p].buffer = (char *)&argv[p].i32;
      in[p].buffer_length = sizeof(int);
      break;

    case 's':
      in[p].buffer = (char *)argv[p].str;
      if(in[p].buffer != NULL) {
        in[p].buffer_type = MYSQL_TYPE_STRING;
        in[p].buffer_length = strlen(in[p].buffer);
      } else {
        in[p].buffer_type = MYSQL_TYPE_NULL;
      }
      break;

    case 'b':
      in[p].buffer = (char *)argv[p].str;
      in[p].buffer_length = argv[p].len;
      in[p].buffer_type = MYSQL_TYPE_STRING;
      break;

    default:
      abort();
    }
  }
  return db_stmt_exec_try(stmt, in, argv, argc);
}

/**
 *
 */
int
db_stmt_exec(db_stmt_t *stmt, const char *fmt, ...)
{
  if(stmt == NULL)
    return -1;

  int p, argc = strlen(fmt);
  db_args_t argv[argc];

  va_list ap;
  va_start(ap, fmt);

  for(p = 0; *fmt; p++, fmt++) {
    argv[p].type = *fmt;
    switch(*fmt) {
    case 'i':
      argv[p].i32 = va_arg(ap, int);
      break;

    case 's':
      argv[p].str = va_arg(ap, char *);
      break;

    case 'b':
      argv[p].str = va_arg(ap, char *);
      argv[p].len = va_arg(ap, int);
      break;

    default:
      abort();
    }
  }

  va_end(ap);
  return db_stmt_execa(stmt, argc, argv);
}


/**
 *
 */
static int
db_stream_rowv(int flags, MYSQL_STMT *s, va_list ap)
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
void
db_stmt_reset(db_stmt_t *s)
{
  mysql_stmt_reset(s->mysql_stmt);
}


/**
 *
 */
int
db_stmt_affected_rows(db_stmt_t *s)
{
  return mysql_stmt_affected_rows(s->mysql_stmt);
}

/**
 *
 */
int
db_stream_row(int flags, db_stmt_t *stmt, ...)
{
  if(stmt == NULL)
    return -1;

  va_list ap;
  va_start(ap, stmt);
  int r = db_stream_rowv(flags, stmt->mysql_stmt, ap);
  va_end(ap);
  return r;
}


/**
 *
 */
static int
db_stream_rowi(int flags, MYSQL_STMT *s, ...)
{
  va_list ap;
  va_start(ap, s);
  int r = db_stream_rowv(flags, s, ap);
  va_end(ap);
  return r;
}


/**
 *
 */
db_err_t
db_begin(db_conn_t *c)
{
  while(1) {
    int err = mysql_query(c->m, "START TRANSACTION");
    if(!err)
      return 0;

    switch(mysql_errno(c->m)) {
    case CR_SERVER_GONE_ERROR:
    case CR_SERVER_LOST:
      if(db_reconnect(c))
        return DB_ERR_OTHER;
      continue;
    case ER_LOCK_DEADLOCK:
      return DB_ERR_DEADLOCK;
    default:
      trace(LOG_ERR, "Unable to start transaction -- %s",
            mysql_error(c->m));
      return DB_ERR_OTHER;
    }
  }
}


/**
 *
 */
int
db_commit(db_conn_t *c)
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
db_rollback(db_conn_t *c)
{
  if(mysql_rollback(c->m))
    trace(LOG_ERR, "Unable to rollback transaction -- %s",
          mysql_error(c->m));
  return 0;
}


/**
 *
 */
static int
run_sql_statement(db_conn_t *c, const char *q)
{
  MYSQL_STMT *s = mysql_stmt_init(c->m);
  if(mysql_stmt_prepare(s, q, strlen(q))) {
    mysql_stmt_close(s);
    return -1;
  }

  if(mysql_stmt_execute(s)) {
    mysql_stmt_close(s);
    return -1;
  }

  mysql_stmt_close(s);
  return 0;
}

/**
 *
 */
static int
get_current_version(db_conn_t *c)
{
  int ver;
  const char *sel   = "SELECT ver from schema_version";
  const char *creat = "CREATE TABLE schema_version (ver INT);";
  const char *ins   = "INSERT INTO schema_version (ver) VALUES (0)";
  MYSQL_STMT *s = mysql_stmt_init(c->m);

  if(mysql_stmt_prepare(s, sel, strlen(sel))) {
    mysql_stmt_close(s);

    trace(LOG_INFO, "Creating schema_version table");

    if(run_sql_statement(c, creat))
      return -1;
    if(run_sql_statement(c, ins))
      return -1;

    ver = 0;

  } else {

    if(mysql_stmt_execute(s)) {
      mysql_stmt_close(s);
      return -1;
    }

    int r = db_stream_rowi(0, s, DB_RESULT_INT(ver));
    if(r) {
      return -1;
    }
    mysql_stmt_close(s);
  }

  return ver;
}

/**
 *
 */
static int
run_multiple_statements(db_conn_t *c, char *s)
{
  char delim = ';';

  while(1) {
    while(*s && *s <= 32)
      s++;

    if(*s == 0)
      break;

    if(!strncmp(s, "DELIMITER ", strlen("DELIMITER "))) {
      s += strlen("DELIMITER ");
      delim = *s++;
      continue;
    }

    char *e = strchr(s, delim);

    if(e)
      *e = 0;

    run_sql_statement(c, s);

    if(!e)
      break;
    s = e + 1;
  }


  return 0;
}

/**
 *
 */
int
db_upgrade_schema(const char *schema_bundle)
{
  char path[256];
  db_conn_t *c = db_get_conn();
  if(c == NULL)
    return -1;

  if(db_begin(c))
    return -1;

  int ver = get_current_version(c);

  trace(LOG_INFO, "Current database schema is at version %d", ver);

  int n;
  for(n = 0; ; n++) {
    snprintf(path, sizeof(path), "%s/%03d.sql", schema_bundle, n + 1);
    if(filebundle_get(path, NULL, NULL))
      break;
  }

  if(n == ver) {
    db_rollback(c);
    return 0;
  }

  if(ver > n) {
    trace(LOG_INFO, "Current DB version is greater than we support, giving up");
    db_rollback(c);
    return -1;
  }

  trace(LOG_INFO, "Want to upgrade database schema from version %d to %d", ver, n);

  while(1) {
    const void *q;
    int len;

    ver++;

    snprintf(path, sizeof(path), "%s/%03d.sql", schema_bundle, ver);
    if(filebundle_get(path, &q, &len)) {
      db_rollback(c);
      return -1;
    }

    char *x = malloc(len + 1);
    memcpy(x, q, len);
    x[len] = 0;
    int r = run_multiple_statements(c, x);
    free(x);
    if(r) {
      db_rollback(c);
      trace(LOG_ERR, "Failed to upgrade DB to version %d", ver);
      return -1;
    }
    trace(LOG_INFO, "DB upgraded to version %d", ver);
    if(ver == n)
      break;
  }


  char setq[256];
  snprintf(setq, sizeof(setq), "UPDATE schema_version SET ver=%d", n);
  run_sql_statement(c, setq);

  db_commit(c);
  return 0;
}
