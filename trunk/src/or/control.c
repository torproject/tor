/* Copyright 2004 Nick Mathewson */
/* See LICENSE for licensing information */
/* $Id$ */

#include "or.h"

#define CONTROL_CMD_ERROR        0x0000
#define CONTROL_CMD_DONE         0x0001
#define CONTROL_CMD_SETCONF      0x0002
#define CONTROL_CMD_GETCONF      0x0003
#define CONTROL_CMD_CONFVALUE    0x0004
#define CONTROL_CMD_SETEVENTS    0x0005
#define CONTROL_CMD_EVENT        0x0006
#define CONTROL_CMD_AUTHENTICATE 0x0007
#define _CONTROL_CMD_MAX_RECOGNIZED 0x0007

#define ERR_UNSPECIFIED             0x0000
#define ERR_UNRECOGNIZED_TYPE       0x0001
#define ERR_UNRECOGNIZED_CONFIG_KEY 0x0002
#define ERR_INVALID_CONFIG_VALUE    0x0003
#define ERR_UNRECOGNIZED_EVENT_CODE 0x0004
#define ERR_UNAUTHORIZED_USER       0x0005
#define ERR_FAILED_AUTHENTICATION   0x0006

#define _EVENT_MIN            0x0001
#define EVENT_CIRCUIT_STATUS  0x0001
#define EVENT_STREAM_STATUS   0x0002
#define EVENT_OR_CONN_STATUS  0x0003
#define EVENT_BANDWIDTH_USED  0x0004
#define EVENT_WARNING         0x0005
#define _EVENT_MAX            0x0005

#define EVENT_IS_INTERESTING(e) (global_event_mask & (1<<(e)))

static const char *CONTROL_COMMANDS[] = {
  "error",
  "done",
  "setconf",
  "getconf",
  "confvalue",
  "setevents",
  "events",
  "authenticate",
};

static uint32_t global_event_mask = 0;

#define AUTHENTICATION_COOKIE_LEN 32
static int authentication_cookie_is_set = 0;
static char authentication_cookie[AUTHENTICATION_COOKIE_LEN];

static void update_global_event_mask(void);
static void send_control_message(connection_t *conn, uint16_t type,
                                 uint16_t len, const char *body);
static void send_control_done(connection_t *conn);
static void send_control_error(connection_t *conn, uint16_t error,
                               const char *message);
static void send_control_event(uint16_t event, uint16_t len, const char *body);
static int handle_control_setconf(connection_t *conn, uint16_t len,
                                  char *body);
static int handle_control_getconf(connection_t *conn, uint16_t len,
                                  const char *body);
static int handle_control_setevents(connection_t *conn, uint16_t len,
                                    const char *body);
static int handle_control_authenticate(connection_t *conn, uint16_t len,
                                       const char *body);

static INLINE const char *
control_cmd_to_string(uint16_t cmd)
{
  return (cmd<=_CONTROL_CMD_MAX_RECOGNIZED) ? CONTROL_COMMANDS[cmd] : "Unknown";
}

static void update_global_event_mask(void)
{
  connection_t **conns;
  int n_conns, i;

  global_event_mask = 0;
  get_connection_array(&conns, &n_conns);
  for (i = 0; i < n_conns; ++i) {
    if (conns[i]->type == CONN_TYPE_CONTROL &&
        conns[i]->state == CONTROL_CONN_STATE_OPEN) {
      global_event_mask |= conns[i]->event_mask;
    }
  }
}

static void
send_control_message(connection_t *conn, uint16_t type, uint16_t len,
                     const char *body)
{
  char buf[4];
  tor_assert(conn);
  tor_assert(len || !body);
  tor_assert(type <= _CONTROL_CMD_MAX_RECOGNIZED);
  set_uint32(buf, htons(len));
  set_uint32(buf+2, htons(type));
  connection_write_to_buf(buf, 4, conn);
  if (len)
    connection_write_to_buf(body, len, conn);
}

static void
send_control_done(connection_t *conn)
{
  send_control_message(conn, CONTROL_CMD_DONE, 0, NULL);
}

static void
send_control_error(connection_t *conn, uint16_t error, const char *message)
{
  char buf[256];
  size_t len;
  set_uint16(buf, htons(error));
  len = strlen(message);
  tor_assert(len < (256-2));
  memcpy(buf+2, message, len);
  send_control_message(conn, CONTROL_CMD_ERROR, (uint16_t)(len+2), buf);
}

static void
send_control_event(uint16_t event, uint16_t len, const char *body)
{
  connection_t **conns;
  int n_conns, i;

  get_connection_array(&conns, &n_conns);
  for (i = 0; i < n_conns; ++i) {
    if (conns[i]->type == CONN_TYPE_CONTROL &&
        conns[i]->state == CONTROL_CONN_STATE_OPEN &&
        conns[i]->event_mask & (1<<event)) {
      send_control_message(conns[i], CONTROL_CMD_EVENT, len, body);
    }
  }
}

static int
handle_control_setconf(connection_t *conn, uint16_t len,
                       char *body)
{
  struct config_line_t *lines=NULL;
  or_options_t *options = get_options();

  if (config_get_lines(body, &lines) < 0) {
    log_fn(LOG_WARN,"Controller gave us config lines we can't parse.");
    send_control_error(conn, ERR_UNSPECIFIED, "Couldn't parse configuration");
    return 0;
  }

  if (config_trial_assign(&options, lines, 1) < 0) {
    log_fn(LOG_WARN,"Controller gave us config lines that didn't validate.");
    send_control_error(conn, ERR_UNSPECIFIED, "Configuration was invalid");
    config_free_lines(lines);
    return 0;
  }

  set_options(options); /* put the new one into place */
  config_free_lines(lines);
  send_control_done(conn);
  return 0;
}

static int
handle_control_getconf(connection_t *conn, uint16_t body_len,
                                  const char *body)
{
  smartlist_t *questions = NULL;
  smartlist_t *answers = NULL;
  char *msg = NULL;
  size_t msg_len;
  or_options_t *options = get_options();

  questions = smartlist_create();
  smartlist_split_string(questions, body, "\n",
                         SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 0);
  answers = smartlist_create();
  SMARTLIST_FOREACH(questions, const char *, q,
  {
    struct config_line_t *answer = config_get_assigned_option(options,q);
    if (!answer) {
      send_control_error(conn, ERR_UNRECOGNIZED_CONFIG_KEY, body);
      goto done;
    } else {
      while (answer) {
        struct config_line_t *next;
        size_t alen = strlen(answer->key)+strlen(answer->value)+2;
        char *astr = tor_malloc(alen);
        tor_snprintf(astr, alen, "%s %s\n", answer->key, answer->value);
        smartlist_add(answers, astr);

        next = answer->next;
        tor_free(answer->key);
        tor_free(answer->value);
        tor_free(answer);
        answer = next;
      }
    }
  });

  msg = smartlist_join_strings(answers, "", 0, &msg_len);
  send_control_message(conn, CONTROL_CMD_CONFVALUE,
                       (uint16_t)msg_len, msg);

 done:
  if (answers) SMARTLIST_FOREACH(answers, char *, cp, tor_free(cp));
  if (questions) SMARTLIST_FOREACH(questions, char *, cp, tor_free(cp));
  smartlist_free(answers);
  smartlist_free(questions);
  tor_free(msg);

  return 0;
}

static int handle_control_setevents(connection_t *conn, uint16_t len,
                                    const char *body)
{
  uint16_t event_code;
  uint32_t event_mask = 0;
  if (len % 2) {
    send_control_error(conn, ERR_UNSPECIFIED,
                       "Odd number of bytes in setevents message");
    return 0;
  }

  for (; len; len -= 2, body += 2) {
    event_code = ntohs(get_uint16(body));
    if (event_code < _EVENT_MIN || event_code > _EVENT_MAX) {
      send_control_error(conn, ERR_UNRECOGNIZED_EVENT_CODE,
                         "Unrecognized event code");
      return 0;
    }
    event_mask |= (1 << event_code);
  }

  conn->event_mask = event_mask;

  update_global_event_mask();
  send_control_done(conn);
  return 0;
}

static int handle_control_authenticate(connection_t *conn, uint16_t len,
                                       const char *body)
{
  or_options_t *options = get_options();
  if (len == AUTHENTICATION_COOKIE_LEN &&
      authentication_cookie_is_set &&
      !memcmp(authentication_cookie, body, len)) {
    goto ok;
  } else if (options->HashedControlPassword) {
    char expected[S2K_SPECIFIER_LEN+DIGEST_LEN];
    char received[DIGEST_LEN];
    if (base64_decode(expected,sizeof(expected),
                      options->HashedControlPassword,
                      strlen(options->HashedControlPassword))<0) {
      /* XXXX009 NM we should warn sooner. */
      log_fn(LOG_WARN,"Couldn't decode HashedControlPassword: invalid base64");
      goto err;
    }
    secret_to_key(received,DIGEST_LEN,body,len,expected);
    if (!memcmp(expected+S2K_SPECIFIER_LEN, received, DIGEST_LEN))
      goto ok;
  }

 err:
  send_control_error(conn, ERR_FAILED_AUTHENTICATION,"Authentication failed");
  return 0;
 ok:
  log_fn(LOG_INFO, "Authenticated control connection (%d)", conn->s);
  send_control_done(conn);
  conn->state = CONTROL_CONN_STATE_OPEN;
  return 0;

}

int connection_control_finished_flushing(connection_t *conn) {
  tor_assert(conn);
  tor_assert(conn->type == CONN_TYPE_CONTROL);

  connection_stop_writing(conn);
  return 0;
}

int connection_control_process_inbuf(connection_t *conn) {
  uint16_t body_len, command_type;
  char *body;

  tor_assert(conn);
  tor_assert(conn->type == CONN_TYPE_CONTROL);

 again:
  switch(fetch_from_buf_control(conn->inbuf, &body_len, &command_type, &body))
    {
    case -1:
      log_fn(LOG_WARN, "Error in control command. Failing.");
      return -1;
    case 0:
      /* Control command not all here yet. Wait. */
      return 0;
    case 1:
      /* We got a command. Process it. */
      break;
    default:
      tor_assert(0);
    }

  /* We got a command.  If we need authentication, only authentication
   * commands will be considered. */
  if (conn->state == CONTROL_CONN_STATE_NEEDAUTH &&
      command_type != CONTROL_CMD_AUTHENTICATE) {
    log_fn(LOG_WARN, "Rejecting '%s' command; authentication needed.",
           control_cmd_to_string(command_type));
    send_control_error(conn, ERR_UNAUTHORIZED_USER, "Authentication required");
    tor_free(body);
    goto again;
  }

  switch(command_type)
    {
    case CONTROL_CMD_SETCONF:
      if (handle_control_setconf(conn, body_len, body))
        return -1;
      break;
    case CONTROL_CMD_GETCONF:
      if (handle_control_getconf(conn, body_len, body))
        return -1;
      break;
    case CONTROL_CMD_SETEVENTS:
      if (handle_control_setevents(conn, body_len, body))
        return -1;
      break;
    case CONTROL_CMD_AUTHENTICATE:
      if (handle_control_authenticate(conn, body_len, body))
        return -1;
      break;
    case CONTROL_CMD_ERROR:
    case CONTROL_CMD_DONE:
    case CONTROL_CMD_CONFVALUE:
    case CONTROL_CMD_EVENT:
      log_fn(LOG_WARN, "Received client-only '%s' command; ignoring.",
             control_cmd_to_string(command_type));
      send_control_error(conn, ERR_UNRECOGNIZED_TYPE,
                         "Command type only valid from server to tor client");
      break;
    default:
      log_fn(LOG_WARN, "Received unrecognized command type %d; ignoring.",
             (int)command_type);
      send_control_error(conn, ERR_UNRECOGNIZED_TYPE,
                         "Unrecognized command type");
      break;
  }
  tor_free(body);
  goto again; /* There might be more data. */
}

int control_event_circuit_status(circuit_t *circ, circuit_status_event_t tp)
{
  char *path, *msg;
  size_t path_len;
  if (!EVENT_IS_INTERESTING(EVENT_CIRCUIT_STATUS))
    return 0;
  tor_assert(circ);
  tor_assert(CIRCUIT_IS_ORIGIN(circ));

  path = circuit_list_path(circ);
  path_len = strlen(path);
  msg = tor_malloc(1+4+path_len+1); /* event, circid, path, NUL. */
  msg[0] = (uint8_t) tp;
  set_uint32(msg+1, htonl(circ->global_identifier));
  strlcpy(msg+5,path,path_len+1);

  send_control_event(EVENT_STREAM_STATUS, (uint16_t)(path_len+6), msg);
  tor_free(path);
  tor_free(msg);
  return 0;
}

int control_event_stream_status(connection_t *conn, stream_status_event_t tp)
{
  char *msg;
  size_t len;
  tor_assert(conn->type == CONN_TYPE_AP);
  tor_assert(conn->socks_request);

  if (!EVENT_IS_INTERESTING(EVENT_STREAM_STATUS))
    return 0;

  len = strlen(conn->socks_request->address);
  msg = tor_malloc(5+len+1);
  msg[0] = (uint8_t) tp;
  set_uint32(msg+1, htonl(conn->s)); /* ???? Is this a security problem? */
  strlcpy(msg+5, conn->socks_request->address, len+1);

  send_control_event(EVENT_STREAM_STATUS, (uint16_t)(5+len+1), msg);
  tor_free(msg);
  return 0;
}

int control_event_or_conn_status(connection_t *conn,or_conn_status_event_t tp)
{
  char buf[HEX_DIGEST_LEN+3]; /* status, dollar, identity, NUL */
  size_t len;

  tor_assert(conn->type == CONN_TYPE_OR);

  if (!EVENT_IS_INTERESTING(EVENT_OR_CONN_STATUS))
    return 0;

  buf[0] = (uint8_t)tp;
  strlcpy(buf+1,conn->nickname,sizeof(buf)-1);
  len = strlen(buf+1);
  send_control_event(EVENT_OR_CONN_STATUS, (uint16_t)(len+1), buf);
  return 0;
}

int control_event_bandwidth_used(uint32_t n_read, uint32_t n_written)
{
  char buf[8];

  if (!EVENT_IS_INTERESTING(EVENT_BANDWIDTH_USED))
    return 0;

  set_uint32(buf, htonl(n_read));
  set_uint32(buf+4, htonl(n_read));
  send_control_event(EVENT_BANDWIDTH_USED, 8, buf);

  return 0;
}

void control_event_logmsg(int severity, const char *msg)
{
  size_t len;
  if (severity > LOG_WARN) /* Less important than warning? ignore for now. */
    return;
  if (!EVENT_IS_INTERESTING(EVENT_WARNING))
    return;

  len = strlen(msg);
  send_control_event(EVENT_WARNING, (uint16_t)(len+1), msg);
}

int init_cookie_authentication(void)
{
  char fname[512];

  /* XXXX009 NM add config option to disable this. */

  tor_snprintf(fname, sizeof(fname), "%s/control_auth_cookie",
               get_data_directory());
  crypto_rand(authentication_cookie, AUTHENTICATION_COOKIE_LEN);
  authentication_cookie_is_set = 1;
  if (write_bytes_to_file(fname, authentication_cookie,
                          AUTHENTICATION_COOKIE_LEN, 1)) {
    log_fn(LOG_WARN,"Error writing authentication cookie.");
    return -1;
  }

  return 0;
}

/*
  Local Variabls:
  mode:c
  indent-tabs-mode:nil
  c-basic-offset:2
  End:
*/
