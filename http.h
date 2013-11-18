/*
 *  tvheadend, HTTP interface
 *  Copyright (C) 2007 Andreas Öman
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

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
#define HTTP_STATUS_BAD_REQUEST  400
#define HTTP_STATUS_UNAUTHORIZED 401
#define HTTP_STATUS_NOT_FOUND    404


typedef struct http_connection {
  tcp_stream_t *hc_ts;

  struct sockaddr_in *hc_peer;
  struct sockaddr_in *hc_self;
  char *hc_representative;

  char *hc_url;
  char *hc_url_orig;
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
  
  char *hc_post_data;
  unsigned int hc_post_len;

  struct rtsp *hc_rtsp_session;

} http_connection_t;


void http_arg_flush(struct http_arg_list *list);

char *http_arg_get(struct http_arg_list *list, const char *name);

int http_arg_get_int(struct http_arg_list *list, const char *name,
                     int def);

void http_arg_set(struct http_arg_list *list,
                  const char *key, const char *val);

void http_error(http_connection_t *hc, int error);

int http_output_html(http_connection_t *hc);

int http_output_content(http_connection_t *hc, const char *content);

void http_redirect(http_connection_t *hc, const char *location);

int http_send_header(http_connection_t *hc, int rc, const char *content,
                     int64_t contentlen, const char *encoding,
                     const char *location, int maxage, const char *range,
                     const char *disposition, const char *transfer_encoding);

typedef int (http_callback_t)(http_connection_t *hc, 
			      const char *remain, void *opaque);

typedef struct http_path {
  LIST_ENTRY(http_path) hp_link;
  const char *hp_path;
  void *hp_opaque;
  http_callback_t *hp_callback;
  int hp_len;
} http_path_t;

http_path_t *http_path_add(const char *path, void *opaque,
			   http_callback_t *callback);



int http_server_init(int port, const char *bindaddr);

int http_access_verify(http_connection_t *hc);

void http_deescape(char *s);
