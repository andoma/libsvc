#pragma once

#include <mysql.h>
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

LIST_HEAD(stmt_list, stmt);

typedef struct conn {
  MYSQL *m;
  struct stmt_list prep_statements;
} conn_t;

conn_t *db_get_conn(void);

void db_init(void);

MYSQL_STMT *db_stmt_get(conn_t *c, const char *str);

int db_stmt_exec(MYSQL_STMT *s, const char *fmt, ...);

int db_stream_row(int flags, MYSQL_STMT *s, ...);

MYSQL_STMT *db_stmt_prep(const char *sql);

void db_stmt_cleanup(MYSQL_STMT **ptr);

#define scoped_db_stmt(x, sql) \
 MYSQL_STMT *x __attribute__((cleanup(db_stmt_cleanup)))=db_stmt_prep(sql);

int db_begin(conn_t *c);

int db_commit(conn_t *c);

int db_rollback(conn_t *c);

int db_upgrade_schema(const char *schema_bundle);
