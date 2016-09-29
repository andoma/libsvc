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

#include "htsbuf.h"
#include "tcp.h"

TAILQ_HEAD(http_arg_list, http_arg);

typedef struct http_arg {
  TAILQ_ENTRY(http_arg) link;
  char *key;
  char *val;
} http_arg_t;

#define HTTP_STATUS_OK           200
#define HTTP_STATUS_PARTIAL_CONTENT 206
#define HTTP_STATUS_FOUND        302
#define HTTP_STATUS_NOT_MODIFIED 304
#define HTTP_STATUS_TEMPORARY_REDIRECT 307
#define HTTP_STATUS_BAD_REQUEST  400
#define HTTP_STATUS_UNAUTHORIZED 401
#define HTTP_STATUS_NOT_FOUND    404
#define HTTP_STATUS_ISE          500


typedef struct http_connection {
  tcp_stream_t *hc_ts;

  struct sockaddr_in *hc_peer;
  struct sockaddr_in *hc_self;
  char *hc_peer_addr;

  char *hc_path;
  char *hc_path_orig;
  const char *hc_remain;

  int hc_keep_alive;

  htsbuf_queue_t hc_reply;

  struct http_arg_list hc_args;

  struct http_arg_list hc_response_headers;

  struct http_arg_list hc_req_args; /* Argumets from GET or POST request */

  enum {
    HTTP_CON_WAIT_REQUEST,
    HTTP_CON_READ_HEADER,
    HTTP_CON_END,
    HTTP_CON_POST_DATA,
  } hc_state;

  enum {
    HTTP_CMD_GET,
    HTTP_CMD_HEAD,
    HTTP_CMD_POST,
    HTTP_CMD_PUT,
    HTTP_CMD_DELETE,
    RTSP_CMD_DESCRIBE,
    RTSP_CMD_OPTIONS,
    RTSP_CMD_SETUP,
    RTSP_CMD_TEARDOWN,
    RTSP_CMD_PLAY,
    RTSP_CMD_PAUSE,
  } hc_cmd;

  enum {
    HTTP_VERSION_1_0,
    HTTP_VERSION_1_1,
    RTSP_VERSION_1_0,
  } hc_version;

  char *hc_username;
  char *hc_password;

  struct config_head *hc_user_config;

  int hc_no_output;

  /* Support for HTTP POST */

  const char *hc_content_type;

  char *hc_post_data;
  unsigned int hc_post_len;

  struct ntv *hc_post_message; // For application/json

  /* Session management */

  struct ntv *hc_session_received;
  struct ntv *hc_session;

} http_connection_t;


void http_arg_flush(struct http_arg_list *list);

char *http_arg_get(struct http_arg_list *list, const char *name);

int http_arg_get_int(struct http_arg_list *list, const char *name,
                     int def);

void http_arg_set(struct http_arg_list *list,
                  const char *key, const char *val);

void http_error(http_connection_t *hc, int error);

int http_err(http_connection_t *hc, int error, const char *str);

int http_output_html(http_connection_t *hc);

int http_output_content(http_connection_t *hc, const char *content);

void http_redirect(http_connection_t *hc, const char *location, int status);

int http_send_100_continue(http_connection_t *hc);

int http_send_header(http_connection_t *hc, int rc, const char *content,
                     int64_t contentlen, const char *encoding,
                     const char *location, int maxage, const char *range,
                     const char *disposition, const char *transfer_encoding);

int http_send_reply(http_connection_t *hc, int rc, const char *content,
                    const char *encoding, const char *location, int maxage);

typedef int (http_callback_t)(http_connection_t *hc,
			      const char *remain, void *opaque);

void http_path_add(const char *path, void *opaque, http_callback_t *callback);

typedef int (http_callback2_t)(http_connection_t *hc, int argc, char **argv,
                               int flags);

#define HTTP_ROUTE_HANDLE_100_CONTINUE 0x1

void http_route_add(const char *path, http_callback2_t *callback, int flags);

int http_server_init(const char *config);

int http_access_verify(http_connection_t *hc);

void http_serve_static(const char *path, const char *filebundle,
                       int send_index_html_on_404);

void http_server_init_session_cookie(const char *password, uint8_t generation);
