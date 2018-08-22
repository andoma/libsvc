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

#include "mbuf.h"
#include "atomic.h"
#include "http_parser.h"
#include "task.h"

struct http_connection;
struct ntv;
struct mbuf;
struct sockaddr;
struct async_fd;

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


typedef struct http_request {
  struct http_connection *hr_connection;
  char *hr_path;
  char *hr_remain;
  char *hr_args;

  int hr_route_flags;  // Copy of flags from route

  struct http_arg_list hr_request_headers;

  struct http_arg_list hr_response_headers;

  struct http_arg_list hr_query_args;

  void *hr_body;
  size_t hr_body_size;
  struct ntv *hr_post_message; // For application/json
  struct ntv *hr_session_received;
  struct ntv *hr_session;

  char *hr_peer_addr;
  char *hr_username;
  char *hr_password;


  mbuf_t hr_reply;

  int64_t hr_req_received;
  int64_t hr_req_process;

  int hr_method;

  unsigned short hr_major;
  unsigned short hr_minor;

  uint8_t hr_keep_alive : 2;
  uint8_t hr_secure_cookies : 1;
  uint8_t hr_no_output : 1;
  uint8_t hr_100_continue_check : 1;


} http_request_t;


typedef void *(http_sniffer_t)(void *opaque, struct http_connection *hc,
                               struct mbuf *mq);

int http_dispatch_local_request(http_request_t *hr);

void http_arg_flush(struct http_arg_list *list);

char *http_arg_get(struct http_arg_list *list, const char *name);

int http_arg_get_int(struct http_arg_list *list, const char *name,
                     int def);

void http_arg_set(struct http_arg_list *list,
                  const char *key, const char *val);

void http_log(http_request_t *hr, int status, const char *str);

void http_error(http_request_t *hc, int error);

int http_err(http_request_t *hc, int error, const char *str);

int http_output_html(http_request_t *hc);

int http_output_content(http_request_t *hc, const char *content);

void http_redirect(http_request_t *hc, const char *location, int status);

int http_send_100_continue(http_request_t *hc);

int http_send_header(http_request_t *hc, int rc, const char *statustxt,
                     const char *content,
                     int64_t contentlen, const char *encoding,
                     const char *location, int maxage, const char *range,
                     const char *disposition, const char *transfer_encoding);

int http_send_reply(http_request_t *hc, int rc, const char *content,
                    const char *encoding, const char *location, int maxage);

void http_send_raw(http_request_t *hc, const void *data, size_t len);

const struct sockaddr *http_connection_get_peer(struct http_connection *hc);

struct async_fd *http_connection_get_af(struct http_connection *hc);

int http_send_chunk(http_request_t *hc, const void *data, size_t len);

int http_wait_send_buffe(http_request_t *hr, int bytes);

typedef int (http_callback_t)(http_request_t *hc,
			      const char *remain, void *opaque);

void http_path_add(const char *path, void *opaque, http_callback_t *callback);

typedef int (http_callback2_t)(http_request_t *hc, int argc, char **argv,
                               int flags);

#define HTTP_ROUTE_HANDLE_100_CONTINUE 0x1
#define HTTP_ROUTE_DISABLE_LOG         0x2

void http_route_add(const char *path, http_callback2_t *callback, int flags);

struct http_server *http_server_init(const char *config);

struct http_server *http_server_create(int port, const char *bind_address,
                                       void *sslctx,
                                       http_sniffer_t *sniffer);

void http_server_destroy(struct http_server *hs);

void http_server_update_sslctx(struct http_server *hs, void *sslctx);

int http_access_verify(http_request_t *hc);

void http_serve_static(const char *path, const char *filebundle);

void http_server_init_session_cookie(const char *password, uint8_t generation);




typedef int (websocket_connected_t)(struct http_request *hr);

typedef void (websocket_receive_t)(void *opaque, int opcode,
                                   const uint8_t *data, size_t len);

typedef void (websocket_disconnected_t)(void *opaque, int error,
                                        const char *errmsg);

void websocket_route_add(const char *path,
                         websocket_connected_t *connected,
                         websocket_receive_t *receive,
                         websocket_disconnected_t *error);

void websocket_send(struct http_connection *hc,
                    int opcode, const void *data, size_t len);

void websocket_sendq(struct http_connection *hc,
                     int opcode, struct mbuf *hq);


void websocket_send_json(struct http_connection *hc, const struct ntv *msg);

void websocket_send_close(struct http_connection *hc, int code,
                          const char *reason);

int websocket_session_start(struct http_request *hr,
                            void *opaque,
                            const char *selected_protocol,
                            int compression_level,
                            int max_backlog);

const char *http_mktime(time_t t, int delta);
