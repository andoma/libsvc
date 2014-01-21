#pragma once

#include "queue.h"

#define DB_STORE_RESULT 0x1

#define DB_RESULT_TAG_STR  1
#define DB_RESULT_TAG_INT  2
#define DB_RESULT_TAG_TIME 3

#define DB_RESULT_STRING(x) DB_RESULT_TAG_STR, x, sizeof(x)
#define DB_RESULT_INT(x)    DB_RESULT_TAG_INT, &x
#define DB_RESULT_TIME(x)   DB_RESULT_TAG_TIME, &x

#define DB_ERR_NO_DATA 1
#define DB_ERR_OK      0
#define DB_ERR_OTHER  -1


typedef struct db_stmt db_stmt_t;
typedef struct db_conn db_conn_t;
typedef struct db_args {
  char type;
  int len;
  union {
    const char *str;
    int i32;
  };
} db_args_t;


db_conn_t *db_get_conn(void);

void db_init(void);

db_stmt_t *db_stmt_get(db_conn_t *c, const char *str);

void db_stmt_reset(db_stmt_t *s);

int db_stmt_exec(db_stmt_t *s, const char *fmt, ...);

int db_stmt_execa(db_stmt_t *stmt, int argc, const db_args_t *argv);

int db_stmt_affected_rows(db_stmt_t *s);

int db_stream_row(int flags, db_stmt_t *s, ...);

db_stmt_t *db_stmt_prep(const char *sql);

void db_stmt_cleanup(db_stmt_t **ptr);

#define scoped_db_stmt(x, sql) \
 db_stmt_t *x __attribute__((cleanup(db_stmt_cleanup)))=db_stmt_prep(sql);

int db_begin(db_conn_t *c);

int db_commit(db_conn_t *c);

int db_rollback(db_conn_t *c);

int db_upgrade_schema(const char *schema_bundle);
