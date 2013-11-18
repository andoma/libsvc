
#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>


#include <stdarg.h>
#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <poll.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>

#include "libsvc/dial.h"
#include "libsvc/queue.h"
#include "libsvc/htsbuf.h"
#include "libsvc/strtab.h"
#include "libsvc/trace.h"
#include "libsvc/misc.h"

#include "cfg.h"
#include "irc.h"
#include "cmd.h"
#include "talloc.h"

#define IRC_NICK_RECLAIM_INTERVAL 60
#define IRC_CHANNEL_RETRY_INTERVAL 10

#define DO_IN(x) (get_ts() + (x) * 1000000LL)

#define IRC_CMD_MAX_PARAMS 64


#define IRC_CMD_NOTICE -2
#define IRC_CMD_JOIN   -3
#define IRC_CMD_PING   -4
#define IRC_CMD_KICK   -5
#define IRC_CMD_NICK   -6

const static struct strtab IRC_cmdtab[] = {
  { "NOTICE",        IRC_CMD_NOTICE },
  { "JOIN",          IRC_CMD_JOIN },
  { "PING",          IRC_CMD_PING },
  { "KICK",          IRC_CMD_KICK },
  { "NICK",          IRC_CMD_NICK },
};

LIST_HEAD(irc_client_list, irc_client);
LIST_HEAD(channel_list, channel);
TAILQ_HEAD(irc_out_msg_queue, irc_out_msg);
TAILQ_HEAD(msg_target_queue, msg_target);


/**
 *
 */
typedef struct irc_out_msg {
  TAILQ_ENTRY(irc_out_msg) iom_link;
  int iom_offset;
  int iom_length;
  char iom_data[0];
} irc_out_msg_t;


/**
 *
 */
typedef struct msg_target {
  TAILQ_ENTRY(msg_target) mt_link;
  struct irc_out_msg_queue mt_q;
} msg_target_t;


#define IRC_CHANNEL_NOT_JOINED    0
#define IRC_CHANNEL_JOIN_PENDING -1
#define IRC_CHANNEL_JOINED       -2

/**
 *
 */
typedef struct channel {
  LIST_ENTRY(channel) c_link;
  char *c_name;
  int c_state;
  int c_want_join;
  msg_target_t c_tgt;

} channel_t;


/**
 *
 */
typedef struct irc_client {

  LIST_ENTRY(irc_client) ic_link;

  pthread_t ic_thread;

  char *ic_current_nick;

  int ic_pipe[2];
  struct pollfd ic_fds[2];
  int ic_fd;

  char *ic_server;

  char ic_registered;                /* Set if we have successfully registered
                                        If this is not set we should not try
                                        to JOIN channels, PRIVMSG targets, etc
                                     */
  int ic_disconnect_sleep;          /* Time to sleep before reconnecting
                                       Reset to 1 when we manage to register
                                    */

  struct irc_out_msg_queue ic_cmdq;
  int64_t ic_cmdq_nextsend;
  int ic_cmdq_mintime;

  struct msg_target_queue ic_msgq;  // PRIVMSG/NOTICE arbitration queue

  int64_t ic_msgq_nextsend;
  int ic_msgq_mintime;

  // Timeouts

  int64_t ic_next_channel_scan;
  int64_t ic_next_reclaim_nick;

  // Configurable stuff

  char *ic_wanted_nick;
  struct channel_list ic_channels;
  int ic_dotrace;

} irc_client_t;


static pthread_mutex_t irc_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct irc_client_list irc_clients;

/**
 *
 */
static void
irc_send(irc_client_t *ic, const char *fmt, ...)
{
  char buf[1024];
  va_list ap;
  va_start(ap, fmt);

  int l = vsnprintf(buf, sizeof(buf)-2, fmt, ap);
  va_end(ap);
  buf[l++]  = '\r';
  buf[l++]  = '\n';

  irc_out_msg_t *iom = malloc(sizeof(irc_out_msg_t) + l);
  iom->iom_offset = 0;
  iom->iom_length = l;
  memcpy(iom->iom_data, buf, l);
  TAILQ_INSERT_TAIL(&ic->ic_cmdq, iom, iom_link);
}


/**
 *
 */
static void
permute_nick(irc_client_t *ic)
{
  char buf[128];
  int len = strcspn(ic->ic_current_nick, "0123456789");
  int v = atoi(ic->ic_current_nick + len) + 1;
  snprintf(buf, sizeof(buf), "%.*s%d", len, ic->ic_current_nick, v);
  free(ic->ic_current_nick);
  ic->ic_current_nick = strdup(buf);
  trace(LOG_INFO, "IRC: %s: Switching current nick to %s", ic->ic_server, buf);
}


/**
 *
 */
static void
irc_check_channels(irc_client_t *ic)
{
  channel_t *c;

  LIST_FOREACH(c, &ic->ic_channels, c_link) {
    if(c->c_want_join) {

      if(c->c_state != IRC_CHANNEL_JOIN_PENDING &&
         c->c_state != IRC_CHANNEL_JOINED) {
        irc_send(ic, "JOIN %s", c->c_name);
        c->c_state = IRC_CHANNEL_JOIN_PENDING;
      }
    }
  }
}


/**
 *
 */
static channel_t *
find_channel(irc_client_t *ic, const char *channel)
{
  channel_t *c;

  LIST_FOREACH(c, &ic->ic_channels, c_link)
    if(!strcmp(c->c_name, channel))
      return c;

  c = calloc(1, sizeof(channel_t));
  c->c_name = strdup(channel);
  TAILQ_INIT(&c->c_tgt.mt_q);
  LIST_INSERT_HEAD(&ic->ic_channels, c, c_link);
  return c;
}


/**
 *
 */
static void
irc_handle_kick(irc_client_t *ic, const char *channel, const char *victim)
{
  int self = !strcmp(ic->ic_current_nick, victim);
  int need_check = 0;

  channel_t *c = find_channel(ic, channel);
  if(self) {
    c->c_state = IRC_CHANNEL_NOT_JOINED;

    if(TAILQ_FIRST(&c->c_tgt.mt_q) != NULL)
      TAILQ_REMOVE(&ic->ic_msgq, &c->c_tgt, mt_link);

    trace(LOG_INFO, "IRC: %s: I was kicked from %s", ic->ic_server, channel);
    need_check = 1;
  }

  if(need_check)
    irc_check_channels(ic);
}


/**
 *
 */
static void
irc_handle_join(irc_client_t *ic, const char *nick, const char *channel)
{
  int self = !strcmp(ic->ic_current_nick, nick);

  channel_t *c = find_channel(ic, channel);
  if(self) {
    c->c_state = IRC_CHANNEL_JOINED;
    trace(LOG_INFO, "IRC: %s: Joined %s%s", ic->ic_server, channel,
          TAILQ_FIRST(&c->c_tgt.mt_q) ?
          ",for which I have some pending messages" : "");
    if(TAILQ_FIRST(&c->c_tgt.mt_q) != NULL)
      TAILQ_INSERT_TAIL(&ic->ic_msgq, &c->c_tgt, mt_link);
  }
}


/**
 *
 */
static void
irc_handle_unable_to_join(irc_client_t *ic, const char *channel, int code)
{
  channel_t *c = find_channel(ic, channel);
  assert(c->c_state == IRC_CHANNEL_JOIN_PENDING);
  c->c_state = code;
  trace(LOG_WARNING, "IRC: %s: Unable to join %s -- reason %d",
        ic->ic_server, channel, c->c_state);

  if(!ic->ic_next_channel_scan)
    ic->ic_next_channel_scan = DO_IN(IRC_CHANNEL_RETRY_INTERVAL);
}


/**
 *
 */
static void
irc_handle_nick(irc_client_t *ic, const char *srcnick, const char *newnick)
{
  if(!strcmp(ic->ic_current_nick, srcnick)) {
    trace(LOG_INFO, "IRC: %s: Changed my nick from %s to %s",
          ic->ic_server, ic->ic_current_nick, newnick);
    free(ic->ic_current_nick);
    ic->ic_current_nick = strdup(newnick);

    if(strcmp(ic->ic_current_nick, ic->ic_wanted_nick))
      ic->ic_next_reclaim_nick = DO_IN(IRC_NICK_RECLAIM_INTERVAL);
  }
}

/**
 *
 */
static int
irc_recv_line(irc_client_t *ic, char *p)
{
  const char *prefix = NULL;
  const char *command = NULL;
  const char *argv[IRC_CMD_MAX_PARAMS];
  int code = -1, argc = 0;
  char *x, *y;

  // Parse prefix
  if(p[0] == ':') {
    prefix = p + 1;
    if((x = strchr(p + 1, ' ')) == NULL) {
      trace(LOG_NOTICE, "IRC: %s: Protocol violation -- Missing space",
            ic->ic_server);
      return 1;
    }
    *x++ = 0;
    p = x;
  }

  if(isdigit(p[0]) && isdigit(p[1]) && isdigit(p[2])) {
    p[3] = 0;
    code = atoi(p);
    p += 4;
  } else {
    command = p;
    if((x = strchr(p, ' ')) == NULL) {
      trace(LOG_NOTICE, "IRC: %s: Protocol violation -- No space after command",
            ic->ic_server);
      return 1;
    }
    *x++ = 0;
    p = x;
  }

  while(1) {
    if(argc == IRC_CMD_MAX_PARAMS) {
      trace(LOG_NOTICE, "IRC: %s: Too many parameters", ic->ic_server);
      return 0;
    }
    if(*p == ':') {
      // Last parameter
      argv[argc++] = p + 1;
      break;
    }
    argv[argc++] = p;
    x = strchr(p, ' ');
    if(x == NULL)
      break;
    *x = 0;
    p = x+1;
  }

  if(code == -1) {

    code = str2val(command, IRC_cmdtab);
    if(code == -1) {
      if(ic->ic_dotrace)
	trace(LOG_DEBUG, "IRC: %s: Unknown command %s", ic->ic_server, command);
      return 0;
    }
  }

  // - Decompose prefix

  const char *srcnick = NULL;
  if(prefix != NULL) {
    x = mystrdupa(prefix);
    if((y = strchr(x, '!')) != NULL) {
      srcnick = x;
      *y = 0;
    }
  }

  // --------------

  switch(code) {

  case 433:
    // Nickname already in use
    if(argc < 1)
      return 1;

    if(strcmp(argv[0], ic->ic_current_nick)) {
      permute_nick(ic);
      irc_send(ic, "NICK %s", ic->ic_current_nick);
    }
    ic->ic_next_reclaim_nick = DO_IN(IRC_NICK_RECLAIM_INTERVAL);
    return 0;

  case 376: // End of MOTD
  case 422: // No MOTD
    ic->ic_registered = 1;
    ic->ic_disconnect_sleep = 1;
    irc_check_channels(ic);
    return 0;

  case 403: // No such channel
  case 405: // Too many channels for client
  case 471: // Channel is full
  case 473: // Invite only
  case 474: // Bannned form channel
  case 475: // Bad key

    if(argc < 2)
      return 1;
    irc_handle_unable_to_join(ic, argv[1], code);
    return 0;

  case IRC_CMD_JOIN:
    if(argc < 1 || srcnick == NULL)
      return 1;

    irc_handle_join(ic, srcnick, argv[0]);
    return 0;


  case IRC_CMD_KICK:
    if(argc < 2)
      return 1;

    irc_handle_kick(ic, argv[0], argv[1]);
    return 0;

  case IRC_CMD_PING:
    if(argc < 1)
      return 1;
    irc_send(ic, "PONG :%s", argv[0]);
    return 0;

  case IRC_CMD_NICK:
    irc_handle_nick(ic, srcnick, argv[0]);
    return 0;

  default:
    return 0;
  }
}


/**
 *
 */
static int
irc_parse_input(irc_client_t *ic, htsbuf_queue_t *q)
{
  while(1) {
    int ll = htsbuf_find(q, 0x0d);
    if(ll == -1)
      return 0;

    char *line = alloca(ll + 1);

    htsbuf_read(q, line, ll);
    htsbuf_drop(q, 2); // Drop \r\n

    line[ll] = 0;
    if(ic->ic_dotrace)
      trace(LOG_DEBUG, "IRC: %s: RECV: %s", ic->ic_server, line);

    if(irc_recv_line(ic, line))
      return 1;
  }
}


/**
 *
 */
static void
irc_client_cleanup(irc_client_t *ic)
{
  ic->ic_registered = 0;

  free(ic->ic_current_nick);
  ic->ic_current_nick = NULL;

  ic->ic_next_reclaim_nick = 0;
  ic->ic_next_channel_scan = 0;

  channel_t *c;

  LIST_FOREACH(c, &ic->ic_channels, c_link) {
    if(TAILQ_FIRST(&c->c_tgt.mt_q) != NULL && c->c_state == IRC_CHANNEL_JOINED)
      TAILQ_REMOVE(&ic->ic_msgq, &c->c_tgt, mt_link);
    c->c_state = IRC_CHANNEL_NOT_JOINED;
  }
}


/**
 *
 */
static void
refresh_cfg(irc_client_t *ic)
{
  cfg_root(root);

  const char *nick = cfg_get_str(root, CFG("ircbot", ic->ic_server, "nick"),
                                 "doozer");

  if(strcmp(nick, ic->ic_wanted_nick)) {
    free(ic->ic_wanted_nick);
    ic->ic_wanted_nick = strdup(nick);
    trace(LOG_INFO, "IRC: %s: Switching nick to %s", ic->ic_server, nick);
    irc_send(ic, "NICK %s", ic->ic_wanted_nick);
  }

  ic->ic_dotrace =
    cfg_get_int(root, CFG("ircbot", "trace"), 0) ||
    cfg_get_int(root, CFG("ircbot", ic->ic_server, "trace"), 0);
}


/**
 *
 */
static int
irc_handle_pipe_command(irc_client_t *ic, char cmd)
{
  switch(cmd) {
  case 'c':
    if(ic->ic_registered)
      irc_check_channels(ic);
    return 0;

  case 'm':
    // New messages will be taken care of in the main loop
    return 0;

  case 'o':
    refresh_cfg(ic);
    return 0;

  default:
    return 0;
  }
}


/**
 *
 */
static int
iom_write(irc_client_t *ic, struct irc_out_msg_queue *q)
{
  irc_out_msg_t *iom = TAILQ_FIRST(q);
  int len = iom->iom_length - iom->iom_offset;
  int r = write(ic->ic_fd, iom->iom_data + iom->iom_offset, len);

  if(r == len) {
    if(ic->ic_dotrace)
      trace(LOG_DEBUG, "IRC: %s: SEND: %.*s", ic->ic_server,
	    iom->iom_length - 2, iom->iom_data);
    TAILQ_REMOVE(q, iom, iom_link);
    free(iom);
    return 0;
  }

  if((r == -1 && errno == EAGAIN) || r == 0) {
    ic->ic_fds[0].events |= POLLOUT;
    return 0;
  }

  if(r == -1) {
    trace(LOG_ERR, "IRC: %s: Write failed -- %s",
          ic->ic_server, strerror(errno));
    return 1;
  }

  iom->iom_offset += r;
  return 0;
}


/**
 *
 */
static void *
irc_thread(void *aux)
{
  irc_client_t *ic = aux;
  int backoff = 5;
  int run = 1;

  ic->ic_fd = -1;
  ic->ic_disconnect_sleep = 1;
  while(run) {

    talloc_cleanup();

    if(ic->ic_fd != -1)
      close(ic->ic_fd);

    trace(LOG_INFO, "IRC: %s: Attempting to connect", ic->ic_server);

    ic->ic_fd = dial(ic->ic_server, 6667, 5000);

    if(ic->ic_fd < 0) {
      backoff = MIN(backoff * 2, 120);
      trace(LOG_ERR, "IRC: %s: Unable to connect -- %s -- Retry in %d seconds",
            ic->ic_server, strerror(-ic->ic_fd), backoff);
      sleep(backoff);
      continue;
    }

    trace(LOG_INFO, "IRC: %s: Connection established", ic->ic_server);

    backoff = 5;

    fcntl(ic->ic_fd, F_SETFL, fcntl(ic->ic_fd, F_GETFL) | O_NONBLOCK);


    ic->ic_fds[0].fd = ic->ic_fd;
    ic->ic_fds[0].revents = 0;
    ic->ic_fds[1].fd = ic->ic_pipe[0];
    ic->ic_fds[1].events = POLLIN | POLLERR | POLLHUP;
    ic->ic_fds[1].revents = 0;

    htsbuf_queue_t recvq;
    htsbuf_queue_init(&recvq, 0);

    irc_send(ic, "NICK %s", ic->ic_wanted_nick);
    irc_send(ic, "USER doozer unset unset :Doozer IRC bot");

    assert(ic->ic_current_nick == NULL);
    ic->ic_current_nick = strdup(ic->ic_wanted_nick);

    while(run) {

      talloc_cleanup();

      int timeout = -1;
      int64_t now = get_ts(), next = INT64_MAX;

      ic->ic_fds[0].events = POLLIN | POLLERR | POLLHUP;

      pthread_mutex_lock(&irc_mutex);

      if(ic->ic_next_channel_scan && now >= ic->ic_next_channel_scan) {
        ic->ic_next_channel_scan = 0;
        irc_check_channels(ic);
      }

      if(ic->ic_next_reclaim_nick && now >= ic->ic_next_reclaim_nick) {
        ic->ic_next_reclaim_nick = 0;
        irc_send(ic, "NICK %s", ic->ic_wanted_nick);
      }

      if(TAILQ_FIRST(&ic->ic_msgq) != NULL && ic->ic_msgq_nextsend <= now) {
        ic->ic_msgq_nextsend = now + ic->ic_msgq_mintime;

        msg_target_t *mt = TAILQ_FIRST(&ic->ic_msgq);
        iom_write(ic, &mt->mt_q);

        TAILQ_REMOVE(&ic->ic_msgq, mt, mt_link);
        if(TAILQ_FIRST(&mt->mt_q) != NULL)
          TAILQ_INSERT_TAIL(&ic->ic_msgq, mt, mt_link);
      }

      if(TAILQ_FIRST(&ic->ic_msgq) != NULL)
        next = MIN(next, ic->ic_msgq_nextsend);

      pthread_mutex_unlock(&irc_mutex);

      if(TAILQ_FIRST(&ic->ic_cmdq) != NULL && ic->ic_cmdq_nextsend <= now) {
        ic->ic_cmdq_nextsend = now + ic->ic_cmdq_mintime;
        iom_write(ic, &ic->ic_cmdq);
      }

      if(TAILQ_FIRST(&ic->ic_cmdq) != NULL)
        next = MIN(next, ic->ic_cmdq_nextsend);

      if(ic->ic_next_channel_scan)
        next = MIN(next, ic->ic_next_channel_scan);

      if(ic->ic_next_reclaim_nick)
        next = MIN(next, ic->ic_next_reclaim_nick);

      if(next <= now)
        timeout = 0;
      else if(next == INT64_MAX)
        timeout = -1;
      else
        timeout = (next - now + 999) / 1000;

      int r = poll(ic->ic_fds, 2, timeout);

      if(r == -1) {
        if(errno == EINTR)
          continue;
        trace(LOG_ERR, "IRC: %s: poll() -- %s", ic->ic_server, strerror(errno));
        break;
      }

      if(r == 0)
        continue;

      if(ic->ic_fds[1].revents & (POLLERR | POLLHUP)) {
        trace(LOG_NOTICE, "IRC: %s: Terminating session", ic->ic_server);
        run = 0;
        break;
      }

      if(ic->ic_fds[1].revents & POLLIN) {
        char c;
        if(read(ic->ic_pipe[0], &c, 1) != 1) {
          trace(LOG_ERR, "IRC: %s: Pipe error -- %s", ic->ic_server, strerror(errno));
          run = 0;
          break;
        }
        pthread_mutex_lock(&irc_mutex);
        r = irc_handle_pipe_command(ic, c);
        pthread_mutex_unlock(&irc_mutex);
        if(r)
          break;
      }

      if(ic->ic_fds[0].revents & (POLLERR | POLLHUP)) {
        int err;
        socklen_t len = sizeof(err);
        getsockopt(ic->ic_fd, SOL_SOCKET, SO_ERROR, &err, &len);
        trace(LOG_ERR, "IRC: %s: Connection lost -- %s", ic->ic_server, strerror(err));
        break;
      }

      if(ic->ic_fds[0].revents & POLLIN) {
        char buf[1024];
        int r = read(ic->ic_fd, buf, sizeof(buf));
        if(r == 0) {
          trace(LOG_ERR, "IRC: %s: Connection lost -- Connection reset by peer",
                ic->ic_server);
          break;
        }
        if(r == -1) {
          trace(LOG_ERR, "IRC: %s: Connection lost -- %s",
                ic->ic_server, strerror(errno));
          break;
        }
        htsbuf_append(&recvq, buf, r);

        pthread_mutex_lock(&irc_mutex);
        r = irc_parse_input(ic, &recvq);
        pthread_mutex_unlock(&irc_mutex);

        if(r) {
          trace(LOG_ERR, "IRC: %s: Protocol violation, disconnecting", ic->ic_server);
          break;
        }
      }
    }
    htsbuf_queue_flush(&recvq);
    close(ic->ic_fd);
    ic->ic_fd = -1;
    if(!run)
      break;
    irc_client_cleanup(ic);
    trace(LOG_INFO, "IRC: %s: Reconnect in %d seconds",
          ic->ic_server, ic->ic_disconnect_sleep);
    sleep(ic->ic_disconnect_sleep);
    ic->ic_disconnect_sleep = MIN(ic->ic_disconnect_sleep * 2, 120);
  }

  if(ic->ic_fd != -1)
    close(ic->ic_fd);

  irc_client_cleanup(ic);
  close(ic->ic_pipe[0]);
  free(ic->ic_wanted_nick);
  free(ic->ic_server);
  free(ic);
  return NULL;
}


/**
 *
 */
static void
irc_client_notify(irc_client_t *ic, char cmd)
{
  if(write(ic->ic_pipe[1], &cmd, 1) < 0) {
    trace(LOG_ERR, "IRC: %s: Pipe write failed -- %s",
          ic->ic_server, strerror(errno));
  }
}


/**
 *
 */
static irc_client_t *
irc_get_server(const char *server)
{
  irc_client_t *ic;

  LIST_FOREACH(ic, &irc_clients, ic_link)
    if(!strcmp(server, ic->ic_server))
      return ic;

  ic = calloc(1, sizeof(irc_client_t));

  if(pipe(ic->ic_pipe)) {
    trace(LOG_ERR, "IRC: %s: Unable create pipe -- %s",
          server, strerror(errno));
    free(ic);
    return NULL;
  }

  LIST_INSERT_HEAD(&irc_clients, ic, ic_link);

  cfg_root(root);

  const char *nick = cfg_get_str(root, CFG("ircbot", server, "nick"), "doozer");

  ic->ic_wanted_nick = strdup(nick);
  ic->ic_server = strdup(server);
  TAILQ_INIT(&ic->ic_cmdq);
  ic->ic_cmdq_mintime = 100000;

  TAILQ_INIT(&ic->ic_msgq);
  ic->ic_msgq_mintime = 1000000;

  pthread_attr_t attr;
  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
  pthread_create(&ic->ic_thread, &attr, irc_thread, ic);
  pthread_attr_destroy(&attr);
  return ic;
}


/**
 *
 */
static channel_t *
irc_get_channel(irc_client_t *ic, const char *channel)
{
  channel_t *c = find_channel(ic, channel);
  if(!c->c_want_join) {
    c->c_want_join = 1;
    irc_client_notify(ic, 'c');
  }
  return c;
}


/**
 *
 */
void
irc_msg_channel(const char *server, const char *channel, const char *str)
{
  pthread_mutex_lock(&irc_mutex);

  irc_client_t *ic = irc_get_server(server);
  if(ic != NULL) {

    channel_t *c = irc_get_channel(ic, channel);
    if(c != NULL) {
      char buf[513];

      while(*str) {
        int len = snprintf(buf, sizeof(buf), "PRIVMSG %s :", channel);
        int rem = strcspn(str, "\n");
        int l = MIN(rem, 510 - len);

        if(l == 0) {
          len += snprintf(buf + len, sizeof(buf) - len, " \r\n");
        } else {
          len += snprintf(buf + len, sizeof(buf) - len, "%.*s\r\n", l, str);
          str += l;
        }

        if(*str == '\n')
          str++;
        irc_out_msg_t *iom = malloc(sizeof(irc_out_msg_t) + len);
        iom->iom_offset = 0;
        iom->iom_length = len;
        memcpy(iom->iom_data, buf, len);
        msg_target_t *mt = &c->c_tgt;

        if(TAILQ_FIRST(&mt->mt_q) == NULL && c->c_state == IRC_CHANNEL_JOINED)
          TAILQ_INSERT_TAIL(&ic->ic_msgq, mt, mt_link);

        TAILQ_INSERT_TAIL(&mt->mt_q, iom, iom_link);
      }
      irc_client_notify(ic, 'm');
    }
  }
  pthread_mutex_unlock(&irc_mutex);
}


/**
 *
 */
void
irc_refresh_config(void)
{
  irc_client_t *ic;

  pthread_mutex_lock(&irc_mutex);

  LIST_FOREACH(ic, &irc_clients, ic_link)
    irc_client_notify(ic, 'o');

  pthread_mutex_unlock(&irc_mutex);

}


static int
irc_say(const char *user,
        int argc, const char **argv, int *intv,
        void (*msg)(void *opaque, const char *fmt, ...),
        void *opaque)
{

  irc_msg_channel(argv[0], argv[1], argv[2]);
  return 0;
}

CMD(irc_say,
    CMD_LITERAL("irc"),
    CMD_LITERAL("say"),
    CMD_VARSTR("server"),
    CMD_VARSTR("channel"),
    CMD_ROL("message")
);
