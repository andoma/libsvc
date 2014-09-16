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
#include <stdio.h>
#include <string.h>

#include "queue.h"
#include "cmd.h"
#include "misc.h"

LIST_HEAD(cmd_node_list, cmd_node);

typedef struct cmd_node {
  LIST_ENTRY(cmd_node) cn_parent_link;
  struct cmd_node_list cn_childs;
  const cmd_token_t *cn_token;
  cmd_invoke_t *cn_invoke;
} cmd_node_t;

static cmd_node_t cmd_root;


/**
 *
 */
int
cmd_exec(const char *line, const char *user,
         void (*msg)(void *opaque, const char *fmt, ...),
         void *opaque)
{
  char *str = mystrdupa(line);
  char *input[64];
  int inputlen = str_tokenize(str, input, 64, -1);

  const char *argv[64];
  int intv[64];
  int argc = 0;
  int i;

  if(inputlen == 0)
    return 0;

  cmd_node_t *cur = &cmd_root, *cn;

  for(i = 0; i < inputlen; i++) {

    LIST_FOREACH(cn, &cur->cn_childs, cn_parent_link) {

      switch(cn->cn_token->type) {
      case CMD_TOKEN_LITERAL:
        if(!strcasecmp(cn->cn_token->str, input[i]))
          goto found;
        break;

      case CMD_TOKEN_VARSTR:
        argv[argc++] = input[i];
        goto found;

      case CMD_TOKEN_ROL:
        argv[argc++] = line + (input[i] - str);
        i = inputlen;
        goto found;
      }
    }
    msg(opaque, "Unknown command: %s", line);
    return 1;

  found:
    cur = cn;
    continue;
  }

  if(cur->cn_invoke == NULL) {
    msg(opaque, "Incomplete command: %s", line);
    return 1;
  }

  return cur->cn_invoke(user, argc, argv, intv, msg, opaque);
}


/**
 *
 */
int
cmd_complete(const char *line, const char *user,
             void (*msg)(void *opaque, const char *fmt, ...),
             void *opaque)
{
  char *str = mystrdupa(line);
  char *input[64];
  int inputlen = str_tokenize(str, input, 64, -1);

  char response[512];

  int resp_len = 0;

  cmd_node_t *cur = &cmd_root, *cn;
  int i;

  for(i = 0; i < inputlen; i++) {

    const char *token = NULL;

    LIST_FOREACH(cn, &cur->cn_childs, cn_parent_link) {

      switch(cn->cn_token->type) {
      case CMD_TOKEN_LITERAL:
        if(!strcasecmp(cn->cn_token->str, input[i])) {
          token = cn->cn_token->str;
          goto found;
        }
        break;

      case CMD_TOKEN_VARSTR:
        token = input[i];
        goto found;

      case CMD_TOKEN_ROL:
        token = line + (input[i] - str);
        i = inputlen;
        goto found;
      }
    }


    // Check if we can find partials and stop here

    LIST_FOREACH(cn, &cur->cn_childs, cn_parent_link) {

      int l = strlen(input[i]);

      switch(cn->cn_token->type) {
      case CMD_TOKEN_LITERAL:
        if(!strncasecmp(cn->cn_token->str, input[i], l)) {
          snprintf(response + resp_len, sizeof(response) - resp_len,
                   "%s%s ", resp_len == 0 ? "" : " ", cn->cn_token->str);
          msg(opaque, "%s", response);
        }
        break;
      }
    }
    return 0;

  found:
    resp_len += snprintf(response + resp_len, sizeof(response) - resp_len,
                         "%s%s", resp_len == 0 ? "" : " ", token);
    cur = cn;
    continue;
  }


  if(cur->cn_invoke != NULL) {
    return 0;
  }

  LIST_FOREACH(cn, &cur->cn_childs, cn_parent_link) {

    switch(cn->cn_token->type) {
    case CMD_TOKEN_LITERAL:
      snprintf(response + resp_len, sizeof(response) - resp_len,
               "%s%s ", resp_len == 0 ? "" : " ", cn->cn_token->str);
      msg(opaque, "%s", response);
      break;
    }
  }
  return 0;
}


/**
 *
 */
static int
cn_cmp(const cmd_node_t *a, const cmd_node_t *b)
{
  if(a->cn_token->type != b->cn_token->type)
    return a->cn_token->type - b->cn_token->type;

  return strcmp(a->cn_token->str, b->cn_token->str);
}

/**
 *
 */
void
cmd_register(const cmd_t *cmd)
{
  cmd_node_t *cur = &cmd_root, *cn;
  const cmd_token_t *ct;

  for(ct = cmd->pattern; ct->type != 0; ct++) {
    LIST_FOREACH(cn, &cur->cn_childs, cn_parent_link)
      if(cn->cn_token->type == ct->type &&
         !strcmp(cn->cn_token->str, ct->str))
        break;

    if(cn != NULL) {
      cur = cn;
      continue;
    }

    cmd_node_t *cn = malloc(sizeof(cmd_node_t));
    cn->cn_token = ct;
    LIST_INSERT_SORTED(&cur->cn_childs, cn, cn_parent_link, cn_cmp);
    LIST_INIT(&cn->cn_childs);
    cur = cn;
  }

  cur->cn_invoke = cmd->invoker;
}


/**
 *
 */
static void
cli_dump_tree0(cmd_node_t *cn, int indent)
{
  if(cn->cn_token != NULL) {
    const char *pre = "";
    const char *post = "";
    if(cn->cn_token->type == CMD_TOKEN_VARSTR) {
      pre = "<";
      post = ">";
    }

    printf("%*.s%s%s%s\n", indent, "", pre, cn->cn_token->str, post);
  }

  cmd_node_t *c;
  LIST_FOREACH(c, &cn->cn_childs, cn_parent_link)
    cli_dump_tree0(c, indent + 4);
}

/**
 *
 */
void
cmd_dump_tree(void)
{
  cli_dump_tree0(&cmd_root, 0);
}
