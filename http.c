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

#include <sys/types.h>
#include <regex.h>
#include <pthread.h>
#include <assert.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <fcntl.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <openssl/evp.h>
#include <openssl/sha.h>

#include "strtab.h"
#include "misc.h"
#include "trace.h"
#include "tcp.h"
#include "http.h"
#include "cfg.h"
#include "talloc.h"
#include "filebundle.h"
#include "ntv.h"
#include "asyncio.h"
#include "websocket.h"

LIST_HEAD(http_connection_list, http_connection);

typedef struct http_server {
  atomic_t hs_refcount;
  const char *hs_config_prefix;

  char *hs_real_ip_header;

  int hs_secure_cookies;

  int hs_port;
  char *hs_bind_address;

} http_server_t;


typedef struct ws_server_path {
  LIST_ENTRY(ws_server_path) wsp_link;
  char *wsp_path;
  websocket_connected_t *wsp_connected;
  websocket_receive_t *wsp_receive;
  websocket_disconnected_t *wsp_disconnected;
} ws_server_path_t;

LIST_HEAD(ws_server_path_list, ws_server_path);

static struct ws_server_path_list websocket_paths;




typedef struct http_connection {
  atomic_t hc_refcount;
  int hc_error;
  asyncio_timer_t hc_timer;

  http_server_t *hc_server;
  struct async_fd *hc_af;

  http_parser hc_parser;
  task_group_t *hc_task_group;

  char *hc_path;
  char *hc_remain;

  char *hc_header_field;
  char *hc_header_value;

  const ws_server_path_t *hc_ws_path;
  websocket_state_t hc_ws_state;
  void *hc_ws_opaque;
  int hc_ws_pong_wait;

  struct http_arg_list hc_request_headers;

  char *hc_peer_addr;

  uint8_t *hc_body;
  size_t hc_body_size;
  uint64_t hc_body_received;





  
} http_connection_t;



typedef struct http_path {
  LIST_ENTRY(http_path) hp_link;
  char *hp_path;
  void *hp_opaque;
  http_callback_t *hp_callback;
  int hp_len;
  int hp_depth;
} http_path_t;


static LIST_HEAD(, http_path) http_paths;


typedef struct http_route {
  LIST_ENTRY(http_route) hr_link;
  int hr_flags;
  char *hr_path;
  regex_t hr_reg;
  int hr_depth;
  http_callback2_t *hr_callback;
} http_route_t;


static LIST_HEAD(, http_route) http_routes;


static void http_parse_query_args(http_request_t *hc, char *args);

static char *generate_session_cookie(http_request_t *hr);

static void get_session_cookie(http_request_t *hr, const char *str);

static int websocket_upgrade(http_connection_t *hc);

static int websocket_packet_input(void *opaque, int opcode,
                                  uint8_t **data, int len);

static int websocket_response(http_request_t *hr);

static void websocket_timer(http_connection_t *hc);

static void http_connection_release(http_connection_t *hc);


/**
 *
 */
static void
http_server_release(http_server_t *hs)
{
  // void
}

/**
 *
 */
static int
http_resolve_path(http_request_t *hr)
{
  http_path_t *hp;
  char *v;
  const char *remain = NULL;

  LIST_FOREACH(hp, &http_paths, hp_link) {
    if(!strncmp(hr->hr_path, hp->hp_path, hp->hp_len)) {
      if(hr->hr_path[hp->hp_len] == 0 || hr->hr_path[hp->hp_len] == '/' ||
	 hr->hr_path[hp->hp_len] == '?')
	break;
    }
  }

  if(hp == NULL)
    return 404;

  v = hr->hr_path + hp->hp_len;


  switch(*v) {
  case 0:
    break;

  case '/':
    if(v[1])
      remain = v + 1;
    break;

  default:
    return 404;
  }


  return hp->hp_callback(hr, remain, hp->hp_opaque);
}


#define MAX_ROUTE_MATCHES 32

/**
 *
 */
static int
http_resolve_route(http_request_t *req, int cont)
{
  http_route_t *hr;
  regmatch_t match[MAX_ROUTE_MATCHES];
  char *argv[MAX_ROUTE_MATCHES];
  int argc;

  LIST_FOREACH(hr, &http_routes, hr_link) {
    if(!regexec(&hr->hr_reg, req->hr_path, MAX_ROUTE_MATCHES, match, 0)) {
      break;
    }
  }
  if(hr == NULL)
    return 404;

  if(cont && !(hr->hr_flags & HTTP_ROUTE_HANDLE_100_CONTINUE))
    return 100;

  for(argc = 0; argc < MAX_ROUTE_MATCHES; argc++) {
    if(match[argc].rm_so == -1)
      break;
    int len = match[argc].rm_eo - match[argc].rm_so;
    char *s = argv[argc] = alloca(len + 1);
    s[len] = 0;
    memcpy(s, req->hr_path + match[argc].rm_so, len);
  }

  return hr->hr_callback(req, argc, argv,
                         cont ? HTTP_ROUTE_HANDLE_100_CONTINUE : 0);
}



/**
 * HTTP status code to string
 */

const static struct strtab HTTP_statuscodes[] = {
#define XX(num, name, string) {#string, HTTP_STATUS_##name},
  HTTP_STATUS_MAP(XX)
#undef XX
};

static const char *
http_rc2str(int code)
{
  return val2str(code, HTTP_statuscodes) ?: "Unknown status code";
}

static const char *httpdays[7] = {
  "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"
};

static const char *httpmonths[12] = {
  "Jan", "Feb", "Mar", "Apr", "May", "Jun",
  "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
};


static const char *
http_req_ver_str(const http_request_t *hr)
{
  if(hr->hr_major == 1 && hr->hr_minor == 1)
    return "HTTP/1.1";
  return "HTTP/1.0";
}


/**
 *
 */
static void
http_log(http_request_t *hr, int status, const char *str)
{
  int64_t d1 = hr->hr_req_process - hr->hr_req_received;
  int64_t d2 = asyncio_now() - hr->hr_req_process;

  int level = LOG_INFO;
  if(status >= 500)
    level = LOG_ERR;
  else if(status >= 400)
    level = LOG_NOTICE;

  trace(level, "HTTP %s -- %d (%s) %s T:%"PRId64"+%"PRId64"us",
        hr->hr_path, status, str, hr->hr_peer_addr, d1, d2);
}

/**
 *
 */
int
http_send_100_continue(http_request_t *hr)
{
  htsbuf_queue_t q;
  htsbuf_queue_init(&q, 0);

  htsbuf_qprintf(&q, "%s 100 Continue\r\n\r\n",
                 http_req_ver_str(hr));
  asyncio_sendq(hr->hr_connection->hc_af, &q, 0);
  http_log(hr, 100, "Continue");
  return 0;
}


/**
 *
 */
static const char *
http_mktime(time_t t, int delta)
{
  struct tm tm0, *tm;

  t += delta;

  tm = gmtime_r(&t, &tm0);

  return tsprintf("%s, %02d %s %d %02d:%02d:%02d GMT",
                  httpdays[tm->tm_wday],	tm->tm_year + 1900,
                  httpmonths[tm->tm_mon], tm->tm_mday,
                  tm->tm_hour, tm->tm_min, tm->tm_sec);
}



void
http_send_raw(http_request_t *hr, const void *data, size_t len)
{
  asyncio_send(hr->hr_connection->hc_af, data, len, 0);
}

/**
 * Transmit a HTTP reply
 */
int
http_send_header(http_request_t *hr, int rc, const char *statustxt,
                 const char *content, int64_t contentlen,
		 const char *encoding, const char *location,
		 int maxage, const char *range,
		 const char *disposition, const char *transfer_encoding)
{
  htsbuf_queue_t hdrs;
  time_t t = time(NULL);

  htsbuf_queue_init(&hdrs, 0);

  if(statustxt == NULL)
    statustxt = http_rc2str(rc);

  htsbuf_qprintf(&hdrs, "%s %d %s\r\n",
                 http_req_ver_str(hr),
		 rc, statustxt);

  htsbuf_qprintf(&hdrs, "Server: %s\r\n", PROGNAME);

  if(ntv_cmp(hr->hr_session, hr->hr_session_received)) {
    const char *cookie = generate_session_cookie(hr);
    if(cookie != NULL) {
      htsbuf_qprintf(&hdrs,
                     "Set-Cookie: %s.session=%s; Path=/; "
                     "expires=%s; HttpOnly%s\r\n",
                     PROGNAME, cookie,
                     http_mktime(t, 365 * 86400),
                     hr->hr_secure_cookies ? "; secure" : "");
    } else {
      htsbuf_qprintf(&hdrs,
                     "Set-Cookie: %s.session=deleted; Path=/; "
                     "expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly%s\r\n",
                     PROGNAME,
                     hr->hr_secure_cookies ? "; secure" : "");
    }
  }

  if(maxage == 0) {
    htsbuf_qprintf(&hdrs, "Cache-Control: no-cache\r\n");
  } else {
    htsbuf_qprintf(&hdrs, "Last-Modified: %s\r\n", http_mktime(t, 0));
    htsbuf_qprintf(&hdrs, "Cache-Control: public, max-age=%d\r\n", maxage);
  }

  if(rc == HTTP_STATUS_UNAUTHORIZED)
    htsbuf_qprintf(&hdrs, "WWW-Authenticate: Basic realm=\"doozer\"\r\n");

  if(contentlen > 0)
    htsbuf_qprintf(&hdrs, "Content-Length: %"PRId64"\r\n", contentlen);
  else
    hr->hr_keep_alive = 0;

  htsbuf_qprintf(&hdrs, "Connection: %s\r\n", 
	      hr->hr_keep_alive ? "Keep-Alive" : "Close");

  if(encoding != NULL)
    htsbuf_qprintf(&hdrs, "Content-Encoding: %s\r\n", encoding);

  if(transfer_encoding != NULL)
    htsbuf_qprintf(&hdrs, "Transfer-Encoding: %s\r\n", transfer_encoding);

  if(location != NULL)
    htsbuf_qprintf(&hdrs, "Location: %s\r\n", location);

  if(content != NULL)
    htsbuf_qprintf(&hdrs, "Content-Type: %s\r\n", content);


  if(range) {
    htsbuf_qprintf(&hdrs, "Accept-Ranges: %s\r\n", "bytes");
    htsbuf_qprintf(&hdrs, "Content-Range: %s\r\n", range);
  }

  if(disposition != NULL)
    htsbuf_qprintf(&hdrs, "Content-Disposition: %s\r\n", disposition);

  http_arg_t *ra;
  TAILQ_FOREACH(ra, &hr->hr_response_headers, link)
    htsbuf_qprintf(&hdrs, "%s: %s\r\n", ra->key, ra->val);

  htsbuf_qprintf(&hdrs, "\r\n");
  //  fprintf(stderr, "-- OUTPUT ------------------\n");
  //  htsbuf_dump_raw_stderr(&hdrs);
  //  fprintf(stderr, "----------------------------\n");

  asyncio_sendq(hr->hr_connection->hc_af, &hdrs, 0);
  return 0;
}



/**
 * Transmit a HTTP reply
 */
int
http_send_reply(http_request_t *hr, int rc, const char *content,
		const char *encoding, const char *location, int maxage)
{
  const char *rcstr = http_rc2str(rc);
  http_log(hr, rc, rcstr);

  if(http_send_header(hr, rc, rcstr, content, hr->hr_reply.hq_size,
                      encoding, location, maxage, 0, NULL, NULL))
    return -1;

  if(hr->hr_no_output)
    return 0;

  asyncio_sendq(hr->hr_connection->hc_af, &hr->hr_reply, 0);
  return 0;
}


/**
 * Send HTTP error back
 */
int
http_err(http_request_t *hr, int error, const char *str)
{
  const char *errtxt;
  if(str != NULL) {
    char *x = mystrdupa(str);
    for(int i = 0; x[i]; i++) {
      if(x[i] < 32)
        x[i] = 32;
    }
    errtxt = x;
  } else {
    errtxt = http_rc2str(error);
  }

  htsbuf_queue_flush(&hr->hr_reply);

  if(error != 304) {

    htsbuf_qprintf(&hr->hr_reply,
                   "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\r\n"
                   "<HTML><HEAD>\r\n"
                   "<TITLE>%d %s</TITLE>\r\n"
                   "</HEAD><BODY>\r\n"
                   "<H1>%d %s</H1>\r\n",
                   error, errtxt, error, errtxt);

    if(str != NULL)
      htsbuf_qprintf(&hr->hr_reply, "<p>%s</p>\r\n", str);

    htsbuf_qprintf(&hr->hr_reply, "</BODY></HTML>\r\n");
  }

  http_log(hr, error, errtxt);

  if(http_send_header(hr, error, str, NULL, hr->hr_reply.hq_size,
                      NULL, NULL, 0, 0, NULL, NULL))
    return 0;

  if(!hr->hr_no_output)
    asyncio_sendq(hr->hr_connection->hc_af, &hr->hr_reply, 0);
  return 0;
}


/**
 * Send HTTP error back
 */
void
http_error(http_request_t *hr, int error)
{
  http_err(hr, error, NULL);
}


/**
 * Send an HTTP OK, simple version for text/html
 */
int
http_output_html(http_request_t *hr)
{
  return http_send_reply(hr, HTTP_STATUS_OK, "text/html; charset=UTF-8",
			 NULL, NULL, 0);
}

/**
 * Send an HTTP OK, simple version for text/html
 */
int
http_output_content(http_request_t *hr, const char *content)
{
  return http_send_reply(hr, HTTP_STATUS_OK, content, NULL, NULL, 0);
}



/**
 * Send an HTTP REDIRECT
 */
void
http_redirect(http_request_t *hr, const char *location, int status)
{
  htsbuf_queue_flush(&hr->hr_reply);

  htsbuf_qprintf(&hr->hr_reply,
		 "<!DOCTYPE html>\r\n"
		 "<HTML><HEAD>\r\n"
		 "<TITLE>Redirect</TITLE>\r\n"
		 "</HEAD><BODY>\r\n"
		 "Please follow <a href=\"%s\">%s</a>\r\n"
		 "</BODY></HTML>\r\n",
		 location, location);

  http_send_reply(hr, status, "text/html", NULL, location, 0);
}


/**
 * Resolve URL and invoke handler
 *
 * If 'cont' is set we are pre-resolving for a 'Expect: 100-continue'
 * request
 *
 * If this function returns non-zero the conncetion will be terminated
 *
 * Normal errors are supposed to be handled without having to disconnection
 * the connection and thus they are sent inside here using http_error()
 *
 */
static void
http_resolve(http_request_t *hr)
{
  int err;

  err = http_resolve_route(hr, 0);

  if(err == 404)
    err = http_resolve_path(hr);

  if(err)
    http_error(hr, err);
}


/**
 *
 */
static void
http_dispatch_request(http_request_t *hr)
{
  char *v, *argv[2];
  int n;
  uint8_t authbuf[150];
  /* Extract authorization */
  if((v = http_arg_get(&hr->hr_request_headers, "Authorization")) != NULL) {
    v = mystrdupa(v);
    if((n = str_tokenize(v, argv, 2, -1)) == 2) {

      if(!strcasecmp(argv[0], "basic")) {
        n = base64_decode(authbuf, argv[1], sizeof(authbuf) - 1);
        authbuf[n] = 0;
        if((n = str_tokenize((char *)authbuf, argv, 2, ':')) == 2) {
          hr->hr_username = strdup(argv[0]);
          hr->hr_password = strdup(argv[1]);
        }
      }
    }
  }

  http_connection_t *hc = hr->hr_connection;
  http_server_t *hs = hc->hc_server;
  if(hs->hs_real_ip_header != NULL) {
    if((v = http_arg_get(&hr->hr_request_headers,
                         hs->hs_real_ip_header)) != NULL) {
      hr->hr_peer_addr = strdup(v);
    }
  }

  if(hr->hr_peer_addr == NULL) {
    hr->hr_peer_addr = strdup(hc->hc_peer_addr);
  }

  if((v = http_arg_get(&hr->hr_request_headers, "Cookie")) != NULL) {
    v = mystrdupa(v);
    char *x = strstr(v, PROGNAME".session=");
    if(x != NULL) {
      x += strlen(PROGNAME".session=");
      char *e = strchr(x, ';');
      if(e != NULL)
        *e = 0;
      get_session_cookie(hr, x);
    }
  }

  if(hr->hr_session_received == NULL)
    hr->hr_session_received = ntv_create_map();

  hr->hr_session = ntv_copy(hr->hr_session_received);

  char *args = strchr(hr->hr_path, '?');
  if(args != NULL) {
    *args = 0;
    http_parse_query_args(hr, args + 1);
  }

  // Websocket connection
  if(hc->hc_ws_path) {
    int err = websocket_response(hr);
    if(err) {
      http_error(hr, err);
      return;
    }

    http_log(hr, 101, "Websocket upgrade");
    hr->hr_keep_alive = 1;
    return;
  }

  // Handle 100-continue stuff
  if(hr->hr_100_continue_check) {
    hr->hr_keep_alive = 1;
    int err = http_resolve_route(hr, 1);

    if(err == 100) {
      http_send_100_continue(hr);
      return;
    }

    if(err != 0)
      http_error(hr, err);

    return;
  }

  // Handle POST/PUT payload
  if(hr->hr_body) {
    /* Parse content-type */
    v = http_arg_get(&hr->hr_request_headers, "Content-Type");
    if(v == NULL) {
      http_err(hr, HTTP_STATUS_BAD_REQUEST, "No Content-Type");
      return;
    }
    v = mystrdupa(v);
    n = str_tokenize(v, argv, 2, ';');
    if(n == 0) {
      http_err(hr, HTTP_STATUS_BAD_REQUEST, "Malformed Content-Type");
      return;
    }

    assert(hr->hr_post_message == NULL);
    if(!strcmp(argv[0], "application/json") &&
       http_arg_get(&hr->hr_request_headers, "content-encoding") == NULL) {
      char errbuf[256];
      hr->hr_post_message = ntv_json_deserialize(hr->hr_body,
                                                 errbuf, sizeof(errbuf));
      if(hr->hr_post_message == NULL) {
        http_err(hr, HTTP_STATUS_BAD_REQUEST, errbuf);
        return;
      }
    }
  }
  http_resolve(hr);
}


/**
 *
 */
static void
http_request_destroy(http_request_t *hr)
{
  free(hr->hr_path);
  free(hr->hr_remain);
  http_arg_flush(&hr->hr_request_headers);
  http_arg_flush(&hr->hr_response_headers);
  http_arg_flush(&hr->hr_query_args);
  free(hr->hr_body);
  free(hr->hr_peer_addr);

  ntv_release(hr->hr_post_message);
  ntv_release(hr->hr_session_received);
  ntv_release(hr->hr_session);
  free(hr->hr_username);
  free(hr->hr_password);

  if(!hr->hr_keep_alive)
    asyncio_shutdown(hr->hr_connection->hc_af);

  http_connection_release(hr->hr_connection);

  free(hr);
}



/**
 * Process a request, extract info from headers, dispatch command
 */
static void
http_dispatch_request_task(void *aux)
{
  http_request_t *hr = aux;
  hr->hr_req_process = asyncio_now();
  http_dispatch_request(hr);
  http_request_destroy(hr);
}





/**
 * Delete all arguments associated with a connection
 */
void
http_arg_flush(struct http_arg_list *list)
{
  http_arg_t *ra;
  while((ra = TAILQ_FIRST(list)) != NULL) {
    TAILQ_REMOVE(list, ra, link);
    free(ra->key);
    free(ra->val);
    free(ra);
  }
}


/**
 * Find an argument associated with a connection
 */
char *
http_arg_get(struct http_arg_list *list, const char *name)
{
  http_arg_t *ra;
  TAILQ_FOREACH(ra, list, link)
    if(!strcasecmp(ra->key, name))
      return ra->val;
  return NULL;
}


/**
 *
 */
int
http_arg_get_int(struct http_arg_list *list, const char *name,
                 int def)
{
  const char *arg = http_arg_get(list, name);
  return arg ? atoi(arg) : def;
}


/**
 * Set an argument associated with a connection
 */
void
http_arg_set(struct http_arg_list *list, const char *key,
             const char *val)
{
  http_arg_t *ra;

  ra = malloc(sizeof(http_arg_t));
  TAILQ_INSERT_TAIL(list, ra, link);
  ra->key = strdup(key);
  ra->val = strdup(val);
}


/**
 *
 */
static int route_cmp(const http_route_t *a, const http_route_t *b)
{
  return a->hr_depth - b->hr_depth;
}

/**
 * Add a regexp'ed route
 */
void
http_route_add(const char *path, http_callback2_t *callback, int flags)
{
  http_route_t *hr = malloc(sizeof(http_route_t));
  int i;

  int len = strlen(path);

  hr->hr_flags = flags;
  hr->hr_depth = 0;

  for(i = 0; i < len; i++)
    if(path[i] == '/')
      hr->hr_depth++;

  char *p = malloc(len + 2);
  p[0] = '^';
  strcpy(p+1, path);

  int rval = regcomp(&hr->hr_reg, p, REG_ICASE | REG_EXTENDED);
  free(p);
  if(rval) {
    char errbuf[256];
    regerror(rval, &hr->hr_reg, errbuf, sizeof(errbuf));
    trace(LOG_ALERT, "Failed to compile regex for HTTP route %s -- %s",
          path, errbuf);
    exit(1);
  }

  hr->hr_path     = strdup(path);
  hr->hr_callback = callback;
  LIST_INSERT_SORTED(&http_routes, hr, hr_link, route_cmp);
}

/**
 *
 */
static int path_cmp(const http_path_t *a, const http_path_t *b)
{
  return b->hp_depth - a->hp_depth;
}

/**
 * Add a callback for a given "virtual path" on our HTTP server
 */
void
http_path_add(const char *path, void *opaque, http_callback_t *callback)
{
  http_path_t *hp = calloc(1, sizeof(http_path_t));

  hp->hp_len      = strlen(path);

  for(int i = 0; i < hp->hp_len; i++)
    if(path[i] == '/')
      hp->hp_depth++;

  hp->hp_path     = strdup(path);
  hp->hp_opaque   = opaque;
  hp->hp_callback = callback;
  LIST_INSERT_SORTED(&http_paths, hp, hp_link, path_cmp);
}


/**
 * Parse arguments of a HTTP GET url, not perfect, but works for us
 */
static void
http_parse_query_args(http_request_t *hr, char *args)
{
  char *k, *v;

  while(args) {
    k = args;
    if((args = strchr(args, '=')) == NULL)
      break;
    *args++ = 0;
    v = args;
    args = strchr(args, '&');

    if(args != NULL)
      *args++ = 0;

    http_deescape(k);
    http_deescape(v);
    http_arg_set(&hr->hr_query_args, k, v);
  }
}



static int
append(char **dst, const char *src, size_t len)
{
  size_t curlen = *dst ? strlen(*dst) : 0;
  char *x = realloc(*dst, curlen + len + 1);
  if(x == NULL)
    return -1;
  memcpy(x + curlen, src, len);
  x[curlen + len] = 0;
  *dst = x;
  return 0;
}


/**
 *
 */
static void
add_current_header(http_connection_t *hc)
{
  if(hc->hc_header_field && hc->hc_header_value) {
    http_arg_t *ra = malloc(sizeof(http_arg_t));
    TAILQ_INSERT_TAIL(&hc->hc_request_headers, ra, link);
    ra->key = hc->hc_header_field;
    ra->val = hc->hc_header_value;

  } else {
    free(hc->hc_header_field);
    free(hc->hc_header_value);
  }
  hc->hc_header_field = NULL;
  hc->hc_header_value = NULL;
}

static int
http_message_begin(http_parser *p)
{
  //  http_connection_t *hc = p->data;
  return 0;
}

static int
http_url(http_parser *p, const char *at, size_t length)
{
  http_connection_t *hc = p->data;
  return append(&hc->hc_path, at, length);
}


static int
http_status(http_parser *p, const char *at, size_t length)
{
  return 0;
}

static int
http_header_field(http_parser *p, const char *at, size_t length)
{
  http_connection_t *hc = p->data;
  add_current_header(hc);
  return append(&hc->hc_header_field, at, length);
}

static int
http_header_value(http_parser *p, const char *at, size_t length)
{
  http_connection_t *hc = p->data;
  return append(&hc->hc_header_value, at, length);
}


/**
 *
 */
static void
http_create_request(http_connection_t *hc, int continue_check)
{
  http_request_t *hr = calloc(1, sizeof(http_request_t));

  hr->hr_connection = hc;
  atomic_inc(&hc->hc_refcount);

  htsbuf_queue_init(&hr->hr_reply, 0);

  TAILQ_INIT(&hr->hr_query_args);
  TAILQ_INIT(&hr->hr_response_headers);

  hr->hr_req_received = asyncio_now();

  if(continue_check) {
    TAILQ_INIT(&hr->hr_request_headers);
    const http_arg_t *ra;
    hr->hr_path = strdup(hc->hc_path);
     TAILQ_FOREACH(ra, &hc->hc_request_headers, link) {
       http_arg_set(&hr->hr_request_headers, ra->key, ra->val);
     }
     hr->hr_100_continue_check = 1;

  } else {

    hr->hr_keep_alive = http_should_keep_alive(&hc->hc_parser);

    TAILQ_MOVE(&hr->hr_request_headers, &hc->hc_request_headers, link);
    TAILQ_INIT(&hc->hc_request_headers);
    hr->hr_path = hc->hc_path;
    hc->hc_path = NULL;

    hr->hr_remain = hc->hc_remain;
    hc->hc_remain = NULL;

    hr->hr_body = hc->hc_body;
    hc->hc_body = NULL;

    hr->hr_body_size = hc->hc_body_received;
  }

  hr->hr_method = hc->hc_parser.method;
  hr->hr_major = hc->hc_parser.http_major;
  hr->hr_minor = hc->hc_parser.http_minor;
  task_run_in_group(http_dispatch_request_task, hr, hc->hc_task_group);
}


/**
 *
 */
static int
http_headers_complete(http_parser *p)
{
  http_connection_t *hc = p->data;
  add_current_header(hc);

  const char *upgrade = http_arg_get(&hc->hc_request_headers, "Upgrade");

  if(!strcasecmp(upgrade ?: "", "websocket")) {
    int err = websocket_upgrade(hc);
    if(!err) {
      return 2;
    }
    return 0;
  }

  const char *expect = http_arg_get(&hc->hc_request_headers, "Expect");
  if(expect != NULL && !strcasecmp(expect, "100-continue")) {
    http_create_request(hc, 1);
  }

  if(p->content_length != UINT64_MAX) {

    if(p->content_length > 1024 * 1024 * 1024) {
      /* Bail out if POST data > 1 GB */
      return -1;
    }
    assert(hc->hc_body == NULL);
    hc->hc_body = malloc(p->content_length + 1);
    if(hc->hc_body == NULL)
      return -1;

    hc->hc_body[p->content_length] = 0;
    hc->hc_body_received = 0;
    hc->hc_body_size = p->content_length;
  }
  return 0;
}

static int
http_body(http_parser *p, const char *at, size_t length)
{
  http_connection_t *hc = p->data;
  if(hc->hc_body == NULL)
    return 1;

  if(hc->hc_body_received + length > hc->hc_body_size)
    return 1;
  memcpy(hc->hc_body + hc->hc_body_received, at, length);
  hc->hc_body_received += length;
  return 0;
}

static int
http_message_complete(http_parser *p)
{
  http_connection_t *hc = p->data;
  http_create_request(hc, 0);
  asyncio_timer_arm_delta(&hc->hc_timer, 60 * 1000000);
  return 0;
}

static const http_parser_settings parser_settings = {
  .on_message_begin    = http_message_begin,
  .on_url              = http_url,
  .on_status           = http_status,
  .on_header_field     = http_header_field,
  .on_header_value     = http_header_value,
  .on_headers_complete = http_headers_complete,
  .on_body             = http_body,
  .on_message_complete = http_message_complete,
  //  .on_chunk_header     = http_chunk_header,
  //  .on_chunk_complete   = http_chunk_complete
};



/**
 *
 */
static void
http_connection_destroy(http_connection_t *hc)
{
  http_server_release(hc->hc_server);
  async_fd_release(hc->hc_af);
  free(hc->hc_path);
  free(hc->hc_remain);
  free(hc->hc_header_field);
  free(hc->hc_header_value);
  task_group_destroy(hc->hc_task_group);

  websocket_free(&hc->hc_ws_state);
  free(hc->hc_peer_addr);
  free(hc);
}


/**
 *
 */
static void
http_connection_release(http_connection_t *hc)
{
  if(atomic_dec(&hc->hc_refcount))
     return;

  http_connection_destroy(hc);
}


/**
 *
 */
static void
http_connection_shutdown_task(void *aux)
{
  http_connection_t *hc = aux;

  if(hc->hc_ws_path != NULL && hc->hc_ws_opaque != NULL)
    hc->hc_ws_path->wsp_disconnected(hc->hc_ws_opaque, hc->hc_error);

  http_connection_release(hc);
}


/**
 *
 */
static void
http_connection_close(http_connection_t *hc)
{
  asyncio_close(hc->hc_af);
  asyncio_timer_disarm(&hc->hc_timer);
  task_run_in_group(http_connection_shutdown_task, hc, hc->hc_task_group);
}


/**
 *
 */
static void
http_server_read(void *opaque, struct htsbuf_queue *hq)
{
  http_connection_t *hc = opaque;
  while(hc->hc_ws_path == NULL) {

    htsbuf_data_t *hd = TAILQ_FIRST(&hq->hq_q);
    if(hd == NULL)
      return;

    size_t r = http_parser_execute(&hc->hc_parser, &parser_settings,
                                   (const void *)hd->hd_data + hd->hd_data_off,
                                   hd->hd_data_len - hd->hd_data_off);
    htsbuf_drop(hq, r);
    if(hc->hc_parser.http_errno) {
      http_connection_close(hc);
      return;
    }
  }

  if(websocket_parse(hq, websocket_packet_input, hc, &hc->hc_ws_state)) {
    http_connection_close(hc);
  }
}


/**
 *
 */
static void
http_server_error(void *opaque, int error)
{
  http_connection_t *hc = opaque;
  hc->hc_error = error;
  http_connection_close(hc);
}


/**
 *
 */
static void
http_server_timeout(void *aux)
{
  http_connection_t *hc = aux;

  if(hc->hc_ws_path != NULL) {
    websocket_timer(hc);
  } else {
    http_connection_close(hc);
  }
}


/**
 *
 */
static int
http_server_accept(void *opaque, int fd, struct sockaddr *peer,
                   struct sockaddr *self)
{
  char tmpbuf[128];
  http_server_t *hs = opaque;
  http_connection_t *hc = calloc(1, sizeof(http_connection_t));

  atomic_set(&hc->hc_refcount, 1);
  TAILQ_INIT(&hc->hc_request_headers);
  http_parser_init(&hc->hc_parser, HTTP_REQUEST);
  hc->hc_parser.data = hc;

  hc->hc_task_group = task_group_create();

  switch(peer->sa_family) {
  case AF_INET:
    if(inet_ntop(AF_INET, &((struct sockaddr_in *)peer)->sin_addr,
                 tmpbuf, sizeof(tmpbuf)) != NULL)
      hc->hc_peer_addr = strdup(tmpbuf);
    break;
  case AF_INET6:
    if(inet_ntop(AF_INET, &((struct sockaddr_in6 *)peer)->sin6_addr,
                 tmpbuf, sizeof(tmpbuf)) != NULL)
      hc->hc_peer_addr = strdup(tmpbuf);
    break;
  }

  if(hc->hc_peer_addr == NULL)
    hc->hc_peer_addr = strdup("0.0.0.0");

  hc->hc_server = hs;
  atomic_inc(&hs->hs_refcount);
  hc->hc_af = asyncio_stream_mt(fd, http_server_read, http_server_error, hc);

  asyncio_timer_init(&hc->hc_timer, http_server_timeout, hc);
  asyncio_timer_arm_delta(&hc->hc_timer, 10 * 1000000);

  asyncio_enable_read(hc->hc_af);

  return 0;
}

/**
 *
 */
static void
http_server_start(void *aux)
{
  http_server_t *hs = aux;

  if(asyncio_bind(hs->hs_bind_address, hs->hs_port,
                  http_server_accept, hs) == NULL) {
    trace(LOG_ERR, "HTTP: Failed to bind %s:%d",
          hs->hs_bind_address, hs->hs_port);
  } else {
    trace(LOG_NOTICE, "HTTP: Listening on %s:%d",
          hs->hs_bind_address, hs->hs_port);
  }
}




/**
 *  Fire up HTTP server
 */
struct http_server *
http_server_init(const char *config_prefix)
{
  cfg_root(cr);

  if(config_prefix == NULL)
    config_prefix = "http";

  http_server_t *hs = calloc(1, sizeof(http_server_t));
  atomic_set(&hs->hs_refcount, 1);
  hs->hs_port = cfg_get_int(cr, CFG(config_prefix, "port"), 9000);
  hs->hs_bind_address =
    strdup(cfg_get_str(cr, CFG(config_prefix, "bindAddress"), "127.0.0.1"));

  hs->hs_config_prefix = strdup(config_prefix);

  const char *real_ip_header =
    cfg_get_str(cr, CFG(config_prefix, "realIpHeader"), NULL);
  hs->hs_real_ip_header = real_ip_header ? strdup(real_ip_header) : NULL;

  hs->hs_secure_cookies = cfg_get_int(cr, CFG(config_prefix, "secureCookies"), 0);

  asyncio_run_task(http_server_start, hs);

  return hs;
}



#if 0

struct bundleserve {
  const char *filepath;
  int send_index_html_on_404;
};



/**
 *
 */
static int
serve_file(http_connection_t *hc, const char *remain, void *opaque)
{
  const struct bundleserve *bs = opaque;
  char path[1024];

  if(remain == NULL)
    remain = "index.html";

  if(strstr(remain, ".."))
    return 400;

  snprintf(path, sizeof(path), "%s/%s", bs->filepath, remain);

  void *data;
  int size;

  const char *ct = NULL;
  const char *postfix = strrchr(remain, '.');
  if(postfix != NULL) {
    postfix++;
    if(!strcmp(postfix, "html")) {
      ct = "text/html";
    } else if(!strcmp(postfix, "css")) {
      ct = "text/css";
    } else if(!strcmp(postfix, "js")) {
      ct = "application/javascript";
    } else if(!strcmp(postfix, "jpeg")) {
      ct = "image/jpeg";
    } else if(!strcmp(postfix, "png")) {
      ct = "image/png";
    }
  }

  if(filebundle_load(path, &data, &size, NULL)) {
    if(!bs->send_index_html_on_404 || ct != NULL)
      return 404;

    remain = "index.html";
    snprintf(path, sizeof(path), "%s/%s", bs->filepath, remain);
    if(filebundle_load(path, &data, &size, NULL)) {
      return 404;
    }
  }

  htsbuf_append(&hc->hc_reply, data, size);

  http_output_content(hc, ct);
  filebundle_free(data);
  return 0;
}


/**
 *
 */
void
http_serve_static(const char *path, const char *filebundle,
                  int send_index_html_on_404)
{
  struct bundleserve *bs = calloc(1, sizeof(struct bundleserve));
  bs->filepath = strdup(filebundle);
  bs->send_index_html_on_404 = send_index_html_on_404;
  http_path_add(path, bs, serve_file);
}
#endif


#define COOKIE_NONCE_LEN 13
#define COOKIE_TAG_LEN 16

static unsigned char ccm_key[24];
static int ccm_key_valid;
static uint8_t cookie_generation;

void
http_server_init_session_cookie(const char *password, uint8_t generation)
{
  if(password == NULL)
    return;

  int r = PKCS5_PBKDF2_HMAC(password, strlen(password),
                            NULL, 0, 1000,
                            EVP_sha256(), sizeof(ccm_key), ccm_key);
  if(!r) {
    trace(LOG_ALERT, "Unable to initialize session cookie keys");
    return;
  }
  ccm_key_valid = 1;
  cookie_generation = generation;
}

/**
 *
 */
static char *
generate_session_cookie(http_request_t *hr)
{
  EVP_CIPHER_CTX *ctx;

  char cookie[4000];
  uint8_t cookiebin[3000] = {0};
  int outlen = 0, tmplen;

  if(ntv_is_empty(hr->hr_session))
    return NULL;

  if(!ccm_key_valid)
    return NULL;

  get_random_bytes(cookiebin, COOKIE_NONCE_LEN);

  struct htsbuf_queue binary;
  htsbuf_queue_init(&binary, 0);
  ntv_binary_serialize(hr->hr_session, &binary);

  if(binary.hq_size > 2500) {
    trace(LOG_ALERT, "Max cookie length exceeded");
    htsbuf_queue_flush(&binary);
    return NULL;
  }

  uint8_t *plaintext = alloca(binary.hq_size + 2);
  int plaintextsize = binary.hq_size + 2;
  plaintext[0] = 0xa0;
  plaintext[1] = cookie_generation;
  htsbuf_read(&binary, plaintext + 2, binary.hq_size);

  ctx = EVP_CIPHER_CTX_new();

  EVP_EncryptInit_ex(ctx, EVP_aes_192_ccm(), NULL, NULL, NULL);

  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, COOKIE_NONCE_LEN, NULL);

  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, COOKIE_TAG_LEN, NULL);

  EVP_EncryptInit_ex(ctx, NULL, NULL, ccm_key, cookiebin);

  /* Encrypt plaintext: can only be called once */
  EVP_EncryptUpdate(ctx, cookiebin + COOKIE_NONCE_LEN + COOKIE_TAG_LEN,
                    &outlen, plaintext, plaintextsize);

  EVP_EncryptFinal_ex(ctx, cookiebin + COOKIE_NONCE_LEN + COOKIE_TAG_LEN,
                      &tmplen);

  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_GET_TAG, COOKIE_TAG_LEN,
                      cookiebin + COOKIE_NONCE_LEN);

  outlen += COOKIE_NONCE_LEN + COOKIE_TAG_LEN;

  EVP_CIPHER_CTX_free(ctx);

  if(base64_encode(cookie, sizeof(cookie), cookiebin, outlen)) {
    trace(LOG_ALERT, "Max cookie length exceeded (base64 encoded)");
    return NULL;
  }

  return tstrdup(cookie);
}


/**
 *
 */
static void
get_session_cookie(http_request_t *hr, const char *str)
{
  EVP_CIPHER_CTX *ctx;
  int outlen, rv;

  if(!ccm_key_valid)
    return;

  int len = strlen(str);
  if(len > 4000)
    return;

  uint8_t *bin = alloca(len);
  int binlen = base64_decode(bin, str, len);
  if(binlen == -1)
    return;

  if(binlen < COOKIE_NONCE_LEN + COOKIE_TAG_LEN + 2)
    return;

  ctx = EVP_CIPHER_CTX_new();
  EVP_DecryptInit_ex(ctx, EVP_aes_192_ccm(), NULL, NULL, NULL);
  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, COOKIE_NONCE_LEN, NULL);
  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG,
                      COOKIE_TAG_LEN, bin + COOKIE_NONCE_LEN);

  EVP_DecryptInit_ex(ctx, NULL, NULL, ccm_key, bin);

  uint8_t *plaintext = alloca(len);

  rv = EVP_DecryptUpdate(ctx, plaintext, &outlen,
                         bin + COOKIE_NONCE_LEN + COOKIE_TAG_LEN,
                         binlen - COOKIE_NONCE_LEN - COOKIE_TAG_LEN);

  EVP_CIPHER_CTX_free(ctx);
  if(rv <= 0)
    return;

  if(outlen < 2)
    return;

  if(plaintext[0] != 0xa0 || plaintext[1] != cookie_generation)
    return;

  hr->hr_session_received = ntv_binary_deserialize(plaintext + 2, outlen - 2);
}


#define WSGUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

static int
websocket_upgrade(http_connection_t *hc)
{
  const ws_server_path_t *wsp;
  LIST_FOREACH(wsp, &websocket_paths, wsp_link) {
    const char *remain = mystrbegins(hc->hc_path, wsp->wsp_path);
    if(remain != NULL) {
      hc->hc_remain = strdup(remain);
      hc->hc_ws_path = wsp;
      return 0;

    }
  }
  return 404;
}


/**
 *
 */
static int
websocket_response(http_request_t *hr)
{
  http_connection_t *hc = hr->hr_connection;
  const ws_server_path_t *wsp = hc->hc_ws_path;

  const char *k = http_arg_get(&hr->hr_request_headers, "Sec-WebSocket-Key");

  if(k == NULL)
    return 400;

  return wsp->wsp_connected(hr);
}


/**
 *
 */
int
websocket_session_start(http_request_t *hr,
                        void *opaque,
                        const char *selected_protocol)

{
  http_connection_t *hc = hr->hr_connection;

  SHA_CTX shactx;
  char sig[64];
  uint8_t d[20];

  hc->hc_ws_opaque = opaque;
  const char *k = http_arg_get(&hr->hr_request_headers, "Sec-WebSocket-Key");

  SHA1_Init(&shactx);
  SHA1_Update(&shactx, (const void *)k, strlen(k));
  SHA1_Update(&shactx, (const void *)WSGUID, strlen(WSGUID));
  SHA1_Final(d, &shactx);

  base64_encode(sig, sizeof(sig), d, 20);

  htsbuf_queue_t out;
  htsbuf_queue_init(&out, 0);

  htsbuf_qprintf(&out,
                 "HTTP/%d.%d 101 Switching Protocols\r\n"
                 "Connection: Upgrade\r\n"
                 "Upgrade: websocket\r\n"
                 "Sec-WebSocket-Accept: %s\r\n",
                 hr->hr_major,
                 hr->hr_minor,
                 sig);

  if(selected_protocol) {
    htsbuf_qprintf(&out, "Sec-WebSocket-Protocol: %s\r\n",
                   selected_protocol);
  }

  htsbuf_qprintf(&out, "\r\n");
  asyncio_sendq(hc->hc_af, &out, 0);
  return 0;
}


/**
 *
 */
void
websocket_route_add(const char *path,
                    websocket_connected_t *connected,
                    websocket_receive_t *receive,
                    websocket_disconnected_t *disconnect)
{
  ws_server_path_t *wsp = calloc(1, sizeof(ws_server_path_t));
  wsp->wsp_path         = strdup(path);
  wsp->wsp_connected    = connected;
  wsp->wsp_receive      = receive;
  wsp->wsp_disconnected = disconnect;
  LIST_INSERT_HEAD(&websocket_paths, wsp, wsp_link);
}



/**
 *
 */
typedef struct ws_server_data {
  TAILQ_ENTRY(ws_server_data) wsd_link;
  http_connection_t *wsd_hc;
  void *wsd_data;
  int wsd_opcode;
  int wsd_arg;

#define WSD_OPCODE_DISCONNECT -1

} ws_server_data_t;


/**
 *
 */
static void
ws_dispatch(void *aux)
{
  ws_server_data_t *wsd = aux;
  http_connection_t *hc = wsd->wsd_hc;
  const ws_server_path_t *wsp = hc->hc_ws_path;

  switch(wsd->wsd_opcode) {
  case WSD_OPCODE_DISCONNECT:
    wsp->wsp_disconnected(hc->hc_ws_opaque, wsd->wsd_arg);
    hc->hc_ws_path = NULL;
    asyncio_shutdown(hc->hc_af);
    break;

  default:
    wsp->wsp_receive(hc->hc_ws_opaque,
                     wsd->wsd_opcode, wsd->wsd_data, wsd->wsd_arg);
    free(wsd->wsd_data);
    break;
  }
  http_connection_release(hc);
  free(wsd);
}



/**
 *
 */
static void
ws_enq_data(http_connection_t *hc, int opcode, void *data, int arg)
{
  ws_server_data_t *wsd = malloc(sizeof(ws_server_data_t));
  wsd->wsd_data = data;
  wsd->wsd_opcode = opcode;
  wsd->wsd_arg = arg;

  wsd->wsd_hc = hc;
  atomic_inc(&hc->hc_refcount);

  task_run_in_group(ws_dispatch, wsd, hc->hc_task_group);
}


void
websocket_send(struct http_connection *hc,
               int opcode, const void *data, size_t len)
{
  uint8_t hdr[WEBSOCKET_MAX_HDR_LEN];
  int hlen = websocket_build_hdr(hdr, opcode, len);
  asyncio_send_with_hdr(hc->hc_af, hdr, hlen, data, len, 0);
}

/**
 *
 */
void
websocket_sendq(struct http_connection *hc, int opcode, htsbuf_queue_t *hq)
{
  uint8_t hdr[WEBSOCKET_MAX_HDR_LEN];
  int hlen = websocket_build_hdr(hdr, opcode, hq->hq_size);
  asyncio_sendq_with_hdr(hc->hc_af, hdr, hlen, hq, 0);
}


/**
 *
 */
void
websocket_send_json(http_connection_t *hc, struct ntv *msg)
{
  htsbuf_queue_t hq;
  htsbuf_queue_init(&hq, 0);

  ntv_json_serialize(msg, &hq, 0);
  websocket_sendq(hc, 1, &hq);
}


/**
 *
 */
void
websocket_send_close(struct http_connection *hc, int code,
                     const char *reason)
{
  htsbuf_queue_t hq;
  htsbuf_queue_init(&hq, 0);
  uint16_t code16 = htons(code);
  htsbuf_append(&hq, &code16, 2);
  if(reason)
    htsbuf_append(&hq, reason, strlen(reason));

  websocket_sendq(hc, 8, &hq);
}


/**
 *
 */
static int
websocket_packet_input(void *opaque, int opcode, uint8_t **data, int len)
{
  http_connection_t *hc = opaque;

  hc->hc_ws_pong_wait = 0;

  switch(opcode) {
  case WS_OPCODE_CLOSE:
    http_connection_close(hc);
    return 0;

  case WS_OPCODE_PING:
    websocket_send(hc, 10, *data, len);
    return 0;

  case WS_OPCODE_PONG:
    return 0;

  default:
    ws_enq_data(hc, opcode, *data, len);
    *data = NULL;
    return 0;
  }
}


static void
websocket_timer(http_connection_t *hc)
{
  if(hc->hc_ws_pong_wait >= 2) {
    asyncio_timer_disarm(&hc->hc_timer);
    ws_enq_data(hc, WSD_OPCODE_DISCONNECT, NULL, 0);
    return;
  }

  uint32_t ping = 0;
  websocket_send(hc, 9, &ping, 4);
  asyncio_timer_arm_delta(&hc->hc_timer, 10 * 1000000);
  hc->hc_ws_pong_wait++;
}
