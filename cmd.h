#pragma once

int cmd_exec(const char *line, const char *user,
             void (*msg)(void *opaque, const char *fmt, ...),
             void *opaque);

int cmd_complete(const char *line, const char *user,
                 void (*msg)(void *opaque, const char *fmt, ...),
                 void *opaque);

#define CMD_TOKEN_LITERAL 1
#define CMD_TOKEN_VARSTR  2

typedef struct cmd_token {
  int type;
  const char *str;
} cmd_token_t;

typedef int (cmd_invoke_t)(const char *user,
                           int argc, char **argv, int *intv,
                           void (*msg)(void *opaque, const char *fmt, ...),
                           void *opaque);

#define CMD_LITERAL(s) {                        \
    .type = CMD_TOKEN_LITERAL,                  \
    .str = s }

#define CMD_VARSTR(s) {                         \
    .type = CMD_TOKEN_VARSTR,                   \
    .str = s }

typedef struct cmd {
  cmd_invoke_t *invoker;
  const cmd_token_t pattern[];
} cmd_t;

void cmd_register(const cmd_t *cmd);

#define CMD_COMBINE1(X,Y) X##Y
#define CMD_COMBINE(X,Y)  CMD_COMBINE1(X,Y)

#define CMD(invoke, x...)                                            \
  static const cmd_t CMD_COMBINE(CLICMD_, __LINE__) = {.invoker = invoke, .pattern = {x, {.type = 0}}}; \
  static void __attribute__((constructor)) CMD_COMBINE(cmd_do_register_, __LINE__)(void) { \
   cmd_register(&CMD_COMBINE(CLICMD_, __LINE__)); \
}

void cmd_dump_tree(void);
