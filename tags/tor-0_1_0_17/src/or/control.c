/* Copyright 2004-2005 Roger Dingledine, Nick Mathewson. */
/* See LICENSE for licensing information */
/* $Id$ */
const char control_c_id[] = "$Id$";

/**
 * \file control.c
 *
 * \brief Implementation for Tor's control-socket interface.
 */

#include "or.h"

/* Protocol outline: a bidirectional stream, over which each side
 * sends a series of messages.  Each message has a two-byte length field,
 * a two-byte typecode, and a variable-length body whose length is
 * given in the length field.
 *
 * By default, the server only sends messages in response to client messages.
 * Every client message gets a message in response.  The client may, however,
 * _request_ that other messages be delivered asynchronously.
 *
 *
 * Every message type is either client-only or server-only, and every
 * server message type is either synchronous-only (only occurs in
 * response to a client request) or asynchronous-only (never is an
 * answer to a client request.
 *
 * See control-spec.txt for full details.
 */

/* Recognized message type codes. */
#define CONTROL_CMD_ERROR        0x0000
#define CONTROL_CMD_DONE         0x0001
#define CONTROL_CMD_SETCONF      0x0002
#define CONTROL_CMD_GETCONF      0x0003
#define CONTROL_CMD_CONFVALUE    0x0004
#define CONTROL_CMD_SETEVENTS    0x0005
#define CONTROL_CMD_EVENT        0x0006
#define CONTROL_CMD_AUTHENTICATE 0x0007
#define CONTROL_CMD_SAVECONF     0x0008
#define CONTROL_CMD_SIGNAL       0x0009
#define CONTROL_CMD_MAPADDRESS   0x000A
#define CONTROL_CMD_GETINFO      0x000B
#define CONTROL_CMD_INFOVALUE    0x000C
#define CONTROL_CMD_EXTENDCIRCUIT  0x000D
#define CONTROL_CMD_ATTACHSTREAM   0x000E
#define CONTROL_CMD_POSTDESCRIPTOR 0x000F
#define CONTROL_CMD_FRAGMENTHEADER 0x0010
#define CONTROL_CMD_FRAGMENT       0x0011
#define CONTROL_CMD_REDIRECTSTREAM 0x0012
#define CONTROL_CMD_CLOSESTREAM    0x0013
#define CONTROL_CMD_CLOSECIRCUIT   0x0014
#define _CONTROL_CMD_MAX_RECOGNIZED 0x0014

/* Recognized error codes. */
#define ERR_UNSPECIFIED             0x0000
#define ERR_INTERNAL                0x0001
#define ERR_UNRECOGNIZED_TYPE       0x0002
#define ERR_SYNTAX                  0x0003
#define ERR_UNRECOGNIZED_CONFIG_KEY 0x0004
#define ERR_INVALID_CONFIG_VALUE    0x0005
#define ERR_UNRECOGNIZED_EVENT_CODE 0x0006
#define ERR_UNAUTHORIZED            0x0007
#define ERR_REJECTED_AUTHENTICATION 0x0008
#define ERR_RESOURCE_EXHAUSETED     0x0009
#define ERR_NO_STREAM               0x000A
#define ERR_NO_CIRC                 0x000B
#define ERR_NO_ROUTER               0x000C

/* Recognized asynchronous event types. */
#define _EVENT_MIN            0x0001
#define EVENT_CIRCUIT_STATUS  0x0001
#define EVENT_STREAM_STATUS   0x0002
#define EVENT_OR_CONN_STATUS  0x0003
#define EVENT_BANDWIDTH_USED  0x0004
#define EVENT_LOG_OBSOLETE    0x0005
#define EVENT_NEW_DESC        0x0006
#define EVENT_DEBUG_MSG       0x0007
#define EVENT_INFO_MSG        0x0008
#define EVENT_NOTICE_MSG      0x0009
#define EVENT_WARN_MSG        0x000A
#define EVENT_ERR_MSG         0x000B
#define _EVENT_MAX            0x000B

/** Array mapping from message type codes to human-readable message
 * type names.  */
static const char * CONTROL_COMMANDS[_CONTROL_CMD_MAX_RECOGNIZED+1] = {
  "error",
  "done",
  "setconf",
  "getconf",
  "confvalue",
  "setevents",
  "events",
  "authenticate",
  "saveconf",
  "signal",
  "mapaddress",
  "getinfo",
  "infovalue",
  "extendcircuit",
  "attachstream",
  "postdescriptor",
  "fragmentheader",
  "fragment",
};

/** Bitfield: The bit 1&lt;&lt;e is set if <b>any</b> open control
 * connection is interested in events of type <b>e</b>.  We use this
 * so that we can decide to skip generating event messages that nobody
 * has interest in without having to walk over the global connection
 * list to find out.
 **/
static uint32_t global_event_mask = 0;

/** Macro: true if any control connection is interested in events of type
 * <b>e</b>. */
#define EVENT_IS_INTERESTING(e) (global_event_mask & (1<<(e)))

/** If we're using cookie-type authentication, how long should our cookies be?
 */
#define AUTHENTICATION_COOKIE_LEN 32

/** If true, we've set authentication_cookie to a secret code and
 * stored it to disk. */
static int authentication_cookie_is_set = 0;
static char authentication_cookie[AUTHENTICATION_COOKIE_LEN];

static void send_control_message(connection_t *conn, uint16_t type,
                                 uint32_t len, const char *body);
static void send_control_done(connection_t *conn);
static void send_control_done2(connection_t *conn, const char *msg, size_t len);
static void send_control_error(connection_t *conn, uint16_t error,
                               const char *message);
static void send_control_event(uint16_t event, uint32_t len, const char *body);
static int handle_control_setconf(connection_t *conn, uint32_t len,
                                  char *body);
static int handle_control_getconf(connection_t *conn, uint32_t len,
                                  const char *body);
static int handle_control_setevents(connection_t *conn, uint32_t len,
                                    const char *body);
static int handle_control_authenticate(connection_t *conn, uint32_t len,
                                       const char *body);
static int handle_control_saveconf(connection_t *conn, uint32_t len,
                                   const char *body);
static int handle_control_signal(connection_t *conn, uint32_t len,
                                 const char *body);
static int handle_control_mapaddress(connection_t *conn, uint32_t len,
                                     const char *body);
static int handle_control_getinfo(connection_t *conn, uint32_t len,
                                  const char *body);
static int handle_control_extendcircuit(connection_t *conn, uint32_t len,
                                        const char *body);
static int handle_control_attachstream(connection_t *conn, uint32_t len,
                                        const char *body);
static int handle_control_postdescriptor(connection_t *conn, uint32_t len,
                                         const char *body);
static int handle_control_redirectstream(connection_t *conn, uint32_t len,
                                         const char *body);
static int handle_control_closestream(connection_t *conn, uint32_t len,
                                      const char *body);
static int handle_control_closecircuit(connection_t *conn, uint32_t len,
                                       const char *body);

/** Given a possibly invalid message type code <b>cmd</b>, return a
 * human-readable string equivalent. */
static INLINE const char *
control_cmd_to_string(uint16_t cmd)
{
  return (cmd<=_CONTROL_CMD_MAX_RECOGNIZED) ? CONTROL_COMMANDS[cmd] : "Unknown";
}

static INLINE int
event_to_log_severity(int event)
{
  switch (event) {
    case EVENT_DEBUG_MSG: return LOG_DEBUG;
    case EVENT_INFO_MSG: return LOG_INFO;
    case EVENT_NOTICE_MSG: return LOG_NOTICE;
    case EVENT_WARN_MSG: return LOG_WARN;
    case EVENT_ERR_MSG: return LOG_ERR;
    default: return -1;
  }
}

static INLINE int
log_severity_to_event(int severity)
{
  switch (severity) {
    case LOG_DEBUG: return EVENT_DEBUG_MSG;
    case LOG_INFO: return EVENT_INFO_MSG;
    case LOG_NOTICE: return EVENT_NOTICE_MSG;
    case LOG_WARN: return EVENT_WARN_MSG;
    case LOG_ERR: return EVENT_ERR_MSG;
    default: return -1;
  }
}

/** Set <b>global_event_mask</b> to the bitwise OR of each live control
 * connection's event_mask field. */
void
control_update_global_event_mask(void)
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

  adjust_event_log_severity();
}

void adjust_event_log_severity(void) {
  int i;
  int min_log_event=EVENT_ERR_MSG, max_log_event=EVENT_DEBUG_MSG;

  for (i = EVENT_DEBUG_MSG; i <= EVENT_ERR_MSG; ++i) {
    if (EVENT_IS_INTERESTING(i)) {
      min_log_event = i;
      break;
    }
  }
  for (i = EVENT_ERR_MSG; i >= EVENT_DEBUG_MSG; --i) {
    if (EVENT_IS_INTERESTING(i)) {
      max_log_event = i;
      break;
    }
  }
  if (EVENT_IS_INTERESTING(EVENT_LOG_OBSOLETE)) {
    if (min_log_event > EVENT_NOTICE_MSG)
      min_log_event = EVENT_NOTICE_MSG;
    if (max_log_event < EVENT_ERR_MSG)
      max_log_event = EVENT_ERR_MSG;
  }
  change_callback_log_severity(event_to_log_severity(min_log_event),
                               event_to_log_severity(max_log_event),
                               control_event_logmsg);
}

/** Send a message of type <b>type</b> containing <b>len</b> bytes
 * from <b>body</b> along the control connection <b>conn</b> */
static void
send_control_message(connection_t *conn, uint16_t type, uint32_t len,
                     const char *body)
{
  char buf[10];
  tor_assert(conn);
  tor_assert(len || !body);
  tor_assert(type <= _CONTROL_CMD_MAX_RECOGNIZED);
  if (len < 65536) {
    set_uint16(buf, htons(len));
    set_uint16(buf+2, htons(type));
    connection_write_to_buf(buf, 4, conn);
    if (len)
      connection_write_to_buf(body, len, conn);
  } else {
    set_uint16(buf, htons(65535));
    set_uint16(buf+2, htons(CONTROL_CMD_FRAGMENTHEADER));
    set_uint16(buf+4, htons(type));
    set_uint32(buf+6, htonl(len));
    connection_write_to_buf(buf, 10, conn);
    connection_write_to_buf(body, 65535-6, conn);
    len -= (65535-6);
    body += (65535-6);
    while (len) {
      size_t chunklen = (len<65535)?len:65535;
      set_uint16(buf, htons((uint16_t)chunklen));
      set_uint16(buf+2, htons(CONTROL_CMD_FRAGMENT));
      connection_write_to_buf(buf, 4, conn);
      connection_write_to_buf(body, chunklen, conn);
      len -= chunklen;
      body += chunklen;
    }
  }
}

/** Send a "DONE" message down the control connection <b>conn</b> */
static void
send_control_done(connection_t *conn)
{
  send_control_message(conn, CONTROL_CMD_DONE, 0, NULL);
}

static void send_control_done2(connection_t *conn, const char *msg, size_t len)
{
  if (len==0)
    len = strlen(msg);
  send_control_message(conn, CONTROL_CMD_DONE, len, msg);
}

/** Send an error message with error code <b>error</b> and body
 * <b>message</b> down the connection <b>conn</b> */
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

/** Send an 'event' message of event type <b>event</b>, containing
 * <b>len</b> bytes in <b>body</b> to every control connection that
 * is interested in it. */
static void
send_control_event(uint16_t event, uint32_t len, const char *body)
{
  connection_t **conns;
  int n_conns, i;
  size_t buflen;
  char *buf;

  tor_assert(event >= _EVENT_MIN && event <= _EVENT_MAX);

  buflen = len + 2;
  buf = tor_malloc_zero(buflen);
  set_uint16(buf, htons(event));
  memcpy(buf+2, body, len);

  get_connection_array(&conns, &n_conns);
  for (i = 0; i < n_conns; ++i) {
    if (conns[i]->type == CONN_TYPE_CONTROL &&
        conns[i]->state == CONTROL_CONN_STATE_OPEN &&
        conns[i]->event_mask & (1<<event)) {
      send_control_message(conns[i], CONTROL_CMD_EVENT, buflen, buf);
      if (event == EVENT_ERR_MSG) {
        _connection_controller_force_write(conns[i]);
      }
    }
  }

  tor_free(buf);
}

/** Called when we receive a SETCONF message: parse the body and try
 * to update our configuration.  Reply with a DONE or ERROR message. */
static int
handle_control_setconf(connection_t *conn, uint32_t len, char *body)
{
  int r;
  struct config_line_t *lines=NULL;

  if (config_get_lines(body, &lines) < 0) {
    log_fn(LOG_WARN,"Controller gave us config lines we can't parse.");
    send_control_error(conn, ERR_SYNTAX, "Couldn't parse configuration");
    return 0;
  }

  if ((r=config_trial_assign(lines, 1)) < 0) {
    log_fn(LOG_WARN,"Controller gave us config lines that didn't validate.");
    if (r==-1) {
      send_control_error(conn, ERR_UNRECOGNIZED_CONFIG_KEY,
                         "Unrecognized option");
    } else {
      send_control_error(conn, ERR_INVALID_CONFIG_VALUE,"Invalid option value");
    }
    config_free_lines(lines);
    return 0;
  }

  config_free_lines(lines);
  if (options_act() < 0) { /* acting on them failed. die. */
    log_fn(LOG_ERR,"Acting on config options left us in a broken state. Dying.");
    exit(1);
  }
  send_control_done(conn);
  return 0;
}

/** Called when we receive a GETCONF message.  Parse the request, and
 * reply with a CONFVALUE or an ERROR message */
static int
handle_control_getconf(connection_t *conn, uint32_t body_len, const char *body)
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
    int recognized = config_option_is_recognized(q);
    if (!recognized) {
      send_control_error(conn, ERR_UNRECOGNIZED_CONFIG_KEY, q);
      goto done;
    } else {
      struct config_line_t *answer = config_get_assigned_option(options,q);

      while (answer) {
        struct config_line_t *next;
        size_t alen = strlen(answer->key)+strlen(answer->value)+3;
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
                       (uint16_t)msg_len, msg_len?msg:NULL);

 done:
  if (answers) {
    SMARTLIST_FOREACH(answers, char *, cp, tor_free(cp));
    smartlist_free(answers);
  }
  if (questions) {
    SMARTLIST_FOREACH(questions, char *, cp, tor_free(cp));
    smartlist_free(questions);
  }
  tor_free(msg);
  return 0;
}

/** Called when we get a SETEVENTS message: update conn->event_mask,
 * and reply with DONE or ERROR. */
static int
handle_control_setevents(connection_t *conn, uint32_t len, const char *body)
{
  uint16_t event_code;
  uint32_t event_mask = 0;
  if (len % 2) {
    send_control_error(conn, ERR_SYNTAX,
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

  control_update_global_event_mask();
  send_control_done(conn);
  return 0;
}

/** Decode the hashed, base64'd password stored in <b>hashed</b>.  If
 * <b>buf</b> is provided, store the hashed password in the first
 * S2K_SPECIFIER_LEN+DIGEST_LEN bytes of <b>buf</b>.  Return 0 on
 * success, -1 on failure.
 */
int
decode_hashed_password(char *buf, const char *hashed)
{
  char decoded[64];
  if (!strcmpstart(hashed, "16:")) {
    if (base16_decode(decoded, sizeof(decoded), hashed+3, strlen(hashed+3))<0
        || strlen(hashed+3) != (S2K_SPECIFIER_LEN+DIGEST_LEN)*2) {
      return -1;
    }
  } else {
      if (base64_decode(decoded, sizeof(decoded), hashed, strlen(hashed))
          != S2K_SPECIFIER_LEN+DIGEST_LEN) {
        return -1;
      }
  }
  if (buf)
    memcpy(buf, decoded, S2K_SPECIFIER_LEN+DIGEST_LEN);
  return 0;
}

/** Called when we get an AUTHENTICATE message.  Check whether the
 * authentication is valid, and if so, update the connection's state to
 * OPEN.  Reply with DONE or ERROR.
 */
static int
handle_control_authenticate(connection_t *conn, uint32_t len, const char *body)
{
  or_options_t *options = get_options();
  if (options->CookieAuthentication) {
    if (len == AUTHENTICATION_COOKIE_LEN &&
        !memcmp(authentication_cookie, body, len)) {
      goto ok;
    }
  } else if (options->HashedControlPassword) {
    char expected[S2K_SPECIFIER_LEN+DIGEST_LEN];
    char received[DIGEST_LEN];
    if (decode_hashed_password(expected, options->HashedControlPassword)<0) {
      log_fn(LOG_WARN,"Couldn't decode HashedControlPassword: invalid base64");
      goto err;
    }
    secret_to_key(received,DIGEST_LEN,body,len,expected);
    if (!memcmp(expected+S2K_SPECIFIER_LEN, received, DIGEST_LEN))
      goto ok;
    goto err;
  } else {
    if (len == 0) {
      /* if Tor doesn't demand any stronger authentication, then
       * the controller can get in with a blank auth line. */
      goto ok;
    }
    goto err;
  }

 err:
  send_control_error(conn, ERR_REJECTED_AUTHENTICATION,"Authentication failed");
  return 0;
 ok:
  log_fn(LOG_INFO, "Authenticated control connection (%d)", conn->s);
  send_control_done(conn);
  conn->state = CONTROL_CONN_STATE_OPEN;
  return 0;
}

static int
handle_control_saveconf(connection_t *conn, uint32_t len,
                        const char *body)
{
  if (save_current_config()<0) {
    send_control_error(conn, ERR_INTERNAL,
                       "Unable to write configuration to disk.");
  } else {
    send_control_done(conn);
  }
  return 0;
}

static int
handle_control_signal(connection_t *conn, uint32_t len,
                      const char *body)
{
  if (len != 1) {
    send_control_error(conn, ERR_SYNTAX,
                       "Body of SIGNAL command too long or too short.");
  } else if (control_signal_act((uint8_t)body[0]) < 0) {
    send_control_error(conn, ERR_SYNTAX, "Unrecognized signal number.");
  } else {
    send_control_done(conn);
  }
  return 0;
}

static int
handle_control_mapaddress(connection_t *conn, uint32_t len, const char *body)
{
  smartlist_t *elts;
  smartlist_t *lines;
  smartlist_t *reply;
  char *r;
  size_t sz;
  lines = smartlist_create();
  elts = smartlist_create();
  reply = smartlist_create();
  smartlist_split_string(lines, body, "\n",
                         SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 0);
  SMARTLIST_FOREACH(lines, char *, line,
  {
    tor_strlower(line);
    smartlist_split_string(elts, line, " ", 0, 2);
    if (smartlist_len(elts) == 2) {
      const char *from = smartlist_get(elts,0);
      const char *to = smartlist_get(elts,1);
      if (!is_plausible_address(from)) {
        log_fn(LOG_WARN,"Skipping invalid argument '%s' in MapAddress msg",from);
      } else if (!is_plausible_address(to)) {
        log_fn(LOG_WARN,"Skipping invalid argument '%s' in MapAddress msg",to);
      } else if (!strcmp(from, ".") || !strcmp(from, "0.0.0.0")) {
        const char *addr = addressmap_register_virtual_address(
              !strcmp(from,".") ? RESOLVED_TYPE_HOSTNAME : RESOLVED_TYPE_IPV4,
               tor_strdup(to));
        if (!addr) {
          log_fn(LOG_WARN,
                 "Unable to allocate address for '%s' in MapAddress msg",
                 safe_str(line));
        } else {
          size_t anslen = strlen(addr)+strlen(to)+2;
          char *ans = tor_malloc(anslen);
          tor_snprintf(ans, anslen, "%s %s", addr, to);
          smartlist_add(reply, ans);
        }
      } else {
        addressmap_register(from, tor_strdup(to), 1);
        smartlist_add(reply, tor_strdup(line));
      }
    } else {
      log_fn(LOG_WARN, "Skipping MapAddress line with wrong number of items.");
    }
    SMARTLIST_FOREACH(elts, char *, cp, tor_free(cp));
    smartlist_clear(elts);
  });
  SMARTLIST_FOREACH(lines, char *, cp, tor_free(cp));
  smartlist_free(lines);
  smartlist_free(elts);

  r = smartlist_join_strings(reply, "\n", 1, &sz);
  send_control_done2(conn,r,sz);

  SMARTLIST_FOREACH(reply, char *, cp, tor_free(cp));
  smartlist_free(reply);
  tor_free(r);
  return 0;
}

/** Lookup the 'getinfo' entry <b>question</b>, and return
 * the answer in <b>*answer</b> (or NULL if key not recognized).
 * Return 0 if success, or -1 if internal error. */
static int
handle_getinfo_helper(const char *question, char **answer)
{
  *answer = NULL; /* unrecognized key by default */
  if (!strcmp(question, "version")) {
    *answer = tor_strdup(VERSION);
  } else if (!strcmpstart(question, "desc/id/")) {
    routerinfo_t *ri = router_get_by_hexdigest(question+strlen("desc/id/"));
    if (ri && ri->signed_descriptor)
      *answer = tor_strdup(ri->signed_descriptor);
  } else if (!strcmpstart(question, "desc/name/")) {
    routerinfo_t *ri = router_get_by_nickname(question+strlen("desc/name/"));
    if (ri && ri->signed_descriptor)
      *answer = tor_strdup(ri->signed_descriptor);
  } else if (!strcmp(question, "network-status")) {
    routerlist_t *routerlist;
    router_get_routerlist(&routerlist);
    if (!routerlist || !routerlist->routers ||
        list_server_status(routerlist->routers, answer) < 0) {
      return -1;
    }
  } else if (!strcmpstart(question, "addr-mappings/")) {
    time_t min_e, max_e;
    smartlist_t *mappings;
    if (!strcmp(question, "addr-mappings/all")) {
      min_e = 0; max_e = TIME_MAX;
    } else if (!strcmp(question, "addr-mappings/cache")) {
      min_e = 2; max_e = TIME_MAX;
    } else if (!strcmp(question, "addr-mappings/config")) {
      min_e = 0; max_e = 0;
    } else if (!strcmp(question, "addr-mappings/control")) {
      min_e = 1; max_e = 1;
    } else {
      return 0;
    }
    mappings = smartlist_create();
    addressmap_get_mappings(mappings, min_e, max_e);
    *answer = smartlist_join_strings(mappings, "\n", 1, NULL);
    SMARTLIST_FOREACH(mappings, char *, cp, tor_free(cp));
    smartlist_free(mappings);
  }
  return 0;
}

static int
handle_control_getinfo(connection_t *conn, uint32_t len, const char *body)
{
  smartlist_t *questions = NULL;
  smartlist_t *answers = NULL;
  char *msg = NULL, *ans;
  size_t msg_len;

  questions = smartlist_create();
  smartlist_split_string(questions, body, "\n",
                         SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 0);
  answers = smartlist_create();
  SMARTLIST_FOREACH(questions, const char *, q,
  {
    if (handle_getinfo_helper(q, &ans) < 0) {
      send_control_error(conn, ERR_INTERNAL, body);
      goto done;
    } if (!ans) {
      send_control_error(conn, ERR_UNRECOGNIZED_CONFIG_KEY, body);
      goto done;
    }
    smartlist_add(answers, tor_strdup(q));
    smartlist_add(answers, ans);
  });

  msg = smartlist_join_strings2(answers, "\0", 1, 1, &msg_len);
  tor_assert(msg_len > 0); /* it will at least be terminated */
  send_control_message(conn, CONTROL_CMD_INFOVALUE,
                       msg_len, msg);

 done:
  if (answers) {
    SMARTLIST_FOREACH(answers, char *, cp, tor_free(cp));
    smartlist_free(answers);
  }
  if (questions) {
    SMARTLIST_FOREACH(questions, char *, cp, tor_free(cp));
    smartlist_free(questions);
  }
  tor_free(msg);

  return 0;
}
static int
handle_control_extendcircuit(connection_t *conn, uint32_t len,
                             const char *body)
{
  smartlist_t *router_nicknames, *routers;
  uint32_t circ_id;
  circuit_t *circ;
  char reply[4];
  if (len<5) {
    send_control_error(conn, ERR_SYNTAX, "extendcircuit message too short");
    return 0;
  }

  router_nicknames = smartlist_create();
  routers = smartlist_create();
  smartlist_split_string(router_nicknames, body+4, ",", 0, 0);
  SMARTLIST_FOREACH(router_nicknames, const char *, n,
    {
      routerinfo_t *r = router_get_by_nickname(n);
      if (!r) {
        send_control_error(conn, ERR_NO_ROUTER, n);
        goto done;
      }
      smartlist_add(routers, r);
    });
  if (!smartlist_len(routers)) {
    send_control_error(conn, ERR_SYNTAX, "No router names provided");
    goto done;
  }

  circ_id = ntohl(get_uint32(body));
  if (!circ_id) {
    /* start a new circuit */
    circ = circuit_init(CIRCUIT_PURPOSE_C_GENERAL, 0, 0, 0);
  } else {
    circ = circuit_get_by_global_id(circ_id);
    if (!circ) {
      send_control_error(conn, ERR_NO_CIRC,
                         "No circuit found with given ID");
      goto done;
    }
  }

  /* now circ refers to something that is ready to be extended */

  SMARTLIST_FOREACH(routers, routerinfo_t *, r,
    {
      circuit_append_new_exit(circ, r);
    });

  /* now that we've populated the cpath, start extending */
  if (!circ_id) {
    if (circuit_handle_first_hop(circ) < 0) {
      circuit_mark_for_close(circ);
      send_control_error(conn, ERR_INTERNAL, "couldn't start circuit");
      goto done;
    }
  } else {
    if (circ->state == CIRCUIT_STATE_OPEN) {
      circ->state = CIRCUIT_STATE_BUILDING;
      if (circuit_send_next_onion_skin(circ) < 0) {
        log_fn(LOG_INFO,"send_next_onion_skin failed; circuit marked for closing.");
        circuit_mark_for_close(circ);
        send_control_error(conn, ERR_INTERNAL, "couldn't send onion skin");
        goto done;
      }
    }
  }

  set_uint32(reply, htonl(circ->global_identifier));
  send_control_done2(conn, reply, sizeof(reply));
 done:
  SMARTLIST_FOREACH(router_nicknames, char *, n, tor_free(n));
  smartlist_free(router_nicknames);
  smartlist_free(routers);
  return 0;
}
static int handle_control_attachstream(connection_t *conn, uint32_t len,
                                        const char *body)
{
  uint32_t conn_id;
  uint32_t circ_id;
  connection_t *ap_conn;
  circuit_t *circ;

  if (len < 8) {
    send_control_error(conn, ERR_SYNTAX, "attachstream message too short");
    return 0;
  }

  conn_id = ntohl(get_uint32(body));
  circ_id = ntohl(get_uint32(body+4));

  if (!(ap_conn = connection_get_by_global_id(conn_id))) {
    send_control_error(conn, ERR_NO_STREAM,
                       "No connection found with given ID");
    return 0;
  }
  if (ap_conn->state != AP_CONN_STATE_CONTROLLER_WAIT) {
    send_control_error(conn, ERR_NO_STREAM,
                       "Connection was not managed by controller.");
    return 0;
  }

  if (!circ_id) {
    ap_conn->state = AP_CONN_STATE_CIRCUIT_WAIT;
    if (connection_ap_handshake_attach_circuit(ap_conn)<0)
      connection_mark_unattached_ap(ap_conn, END_STREAM_REASON_CANT_ATTACH);
    send_control_done(conn);
    return 0;
  }

  if (!(circ = circuit_get_by_global_id(circ_id))) {
    send_control_error(conn, ERR_NO_CIRC, "No circuit found with given ID");
    return 0;
  }
  if (circ->state != CIRCUIT_STATE_OPEN) {
    send_control_error(conn, ERR_INTERNAL, "Refuse to attach stream to non-open circ.");
    return 0;
  }
  if (connection_ap_handshake_attach_chosen_circuit(ap_conn, circ) != 1) {
    send_control_error(conn, ERR_INTERNAL, "Unable to attach stream.");
    return 0;
  }
  send_control_done(conn);
  return 0;
}
static int
handle_control_postdescriptor(connection_t *conn, uint32_t len,
                              const char *body)
{
  const char *msg=NULL;
  switch (router_load_single_router(body, &msg)) {
  case -1:
    send_control_error(conn,ERR_SYNTAX,msg?msg: "Could not parse descriptor");
    break;
  case 0:
    send_control_done2(conn,msg?msg: "Descriptor not added",0);
    break;
  case 1:
    send_control_done(conn);
    break;
  }

  return 0;
}
static int
handle_control_redirectstream(connection_t *conn, uint32_t len,
                              const char *body)
{
  connection_t *ap_conn;
  uint32_t conn_id;
  if (len < 6) {
    send_control_error(conn, ERR_SYNTAX, "redirectstream message too short");
    return 0;
  }
  conn_id = ntohl(get_uint32(body));

  if (!(ap_conn = connection_get_by_global_id(conn_id))
      || ap_conn->state != CONN_TYPE_AP
      || !ap_conn->socks_request) {
    send_control_error(conn, ERR_NO_STREAM,
                       "No AP connection found with given ID");
    return 0;
  }
  strlcpy(ap_conn->socks_request->address, body+4,
          sizeof(ap_conn->socks_request->address));

  send_control_done(conn);
  return 0;
}
static int
handle_control_closestream(connection_t *conn, uint32_t len,
                           const char *body)
{
  uint32_t conn_id;
  connection_t *ap_conn;
  uint8_t reason;

  if (len < 6) {
    send_control_error(conn, ERR_SYNTAX, "closestream message too short");
    return 0;
  }

  conn_id = ntohl(get_uint32(body));
  reason = *(uint8_t*)(body+4);

  if (!(ap_conn = connection_get_by_global_id(conn_id))
      || ap_conn->state != CONN_TYPE_AP
      || !ap_conn->socks_request) {
    send_control_error(conn, ERR_NO_STREAM,
                       "No AP connection found with given ID");
    return 0;
  }
  connection_mark_unattached_ap(ap_conn, reason);
  send_control_done(conn);
  return 0;
}

static int
handle_control_closecircuit(connection_t *conn, uint32_t len,
                            const char *body)
{
  uint32_t circ_id;
  circuit_t *circ;
  int safe;

  if (len < 5) {
    send_control_error(conn, ERR_SYNTAX, "closecircuit message too short");
    return 0;
  }
  circ_id = ntohl(get_uint32(body));
  safe = (*(uint8_t*)(body+4)) & 1;

  if (!(circ = circuit_get_by_global_id(circ_id))) {
    send_control_error(conn, ERR_NO_CIRC,
                       "No circuit found with given ID");
    return 0;
  }

  if (!safe || !circ->p_streams) {
    circuit_mark_for_close(circ);
  }

  send_control_done(conn);
  return 0;
}

static int
handle_control_fragments(connection_t *conn, uint16_t command_type,
                         uint32_t body_len, char *body)
{
  if (command_type == CONTROL_CMD_FRAGMENTHEADER) {
    if (conn->incoming_cmd) {
      log_fn(LOG_WARN, "Dropping incomplete fragmented command");
      tor_free(conn->incoming_cmd);
    }
    if (body_len < 6) {
      send_control_error(conn, ERR_SYNTAX, "FRAGMENTHEADER too short.");
      return 0;
    }
    conn->incoming_cmd_type = ntohs(get_uint16(body));
    conn->incoming_cmd_len = ntohl(get_uint32(body+2));
    conn->incoming_cmd_cur_len = 0;
    conn->incoming_cmd = tor_malloc(conn->incoming_cmd_len);
    body += 6;
    body_len -= 6;
  } else if (command_type == CONTROL_CMD_FRAGMENT) {
    if (!conn->incoming_cmd) {
      send_control_error(conn, ERR_SYNTAX, "Out-of-place FRAGMENT");
      return 0;
    }
  } else {
    tor_assert(0);
  }

  if (conn->incoming_cmd_cur_len + body_len > conn->incoming_cmd_len) {
    tor_free(conn->incoming_cmd);
    send_control_error(conn, ERR_SYNTAX,
                       "Fragmented data exceeds declared length");
    return 0;
  }
  memcpy(conn->incoming_cmd + conn->incoming_cmd_cur_len,
         body, body_len);
  conn->incoming_cmd_cur_len += body_len;
  return 0;
}

/** Called when <b>conn</b> has no more bytes left on its outbuf. */
int
connection_control_finished_flushing(connection_t *conn) {
  tor_assert(conn);
  tor_assert(conn->type == CONN_TYPE_CONTROL);

  connection_stop_writing(conn);
  return 0;
}

/** Called when <b>conn</b> has gotten its socket closed. */
int connection_control_reached_eof(connection_t *conn) {
  log_fn(LOG_INFO,"Control connection reached EOF. Closing.");
  connection_mark_for_close(conn);
  return 0;
}

/** Called when <b>conn</b> has received more bytes on its inbuf.
 */
int
connection_control_process_inbuf(connection_t *conn) {
  uint32_t body_len;
  uint16_t command_type;
  char *body;

  tor_assert(conn);
  tor_assert(conn->type == CONN_TYPE_CONTROL);

 again:
  /* Try to suck a control message from the buffer. */
  switch (fetch_from_buf_control(conn->inbuf, &body_len, &command_type, &body))
    {
    case -1:
      tor_free(body);
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
    send_control_error(conn, ERR_UNAUTHORIZED, "Authentication required");
    tor_free(body);
    goto again;
  }

  if (command_type == CONTROL_CMD_FRAGMENTHEADER ||
      command_type == CONTROL_CMD_FRAGMENT) {
    if (handle_control_fragments(conn, command_type, body_len, body))
      return -1;
    tor_free(body);
    if (conn->incoming_cmd_cur_len != conn->incoming_cmd_len)
      goto again;

    command_type = conn->incoming_cmd_type;
    body_len = conn->incoming_cmd_len;
    body = conn->incoming_cmd;
    conn->incoming_cmd = NULL;
  } else if (conn->incoming_cmd) {
    log_fn(LOG_WARN, "Dropping incomplete fragmented command");
    tor_free(conn->incoming_cmd);
  }

  /* Okay, we're willing to process the command. */
  switch (command_type)
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
    case CONTROL_CMD_SAVECONF:
      if (handle_control_saveconf(conn, body_len, body))
        return -1;
      break;
    case CONTROL_CMD_SIGNAL:
      if (handle_control_signal(conn, body_len, body))
        return -1;
      break;
    case CONTROL_CMD_MAPADDRESS:
      if (handle_control_mapaddress(conn, body_len, body))
        return -1;
      break;
    case CONTROL_CMD_GETINFO:
      if (handle_control_getinfo(conn, body_len, body))
        return -1;
      break;
    case CONTROL_CMD_EXTENDCIRCUIT:
      if (handle_control_extendcircuit(conn, body_len, body))
        return -1;
      break;
    case CONTROL_CMD_ATTACHSTREAM:
      if (handle_control_attachstream(conn, body_len, body))
        return -1;
      break;
    case CONTROL_CMD_POSTDESCRIPTOR:
      if (handle_control_postdescriptor(conn, body_len, body))
        return -1;
      break;
    case CONTROL_CMD_REDIRECTSTREAM:
      if (handle_control_redirectstream(conn, body_len, body))
        return -1;
      break;
    case CONTROL_CMD_CLOSESTREAM:
      if (handle_control_closestream(conn, body_len, body))
        return -1;
      break;
    case CONTROL_CMD_CLOSECIRCUIT:
      if (handle_control_closecircuit(conn, body_len, body))
        return -1;
      break;
    case CONTROL_CMD_ERROR:
    case CONTROL_CMD_DONE:
    case CONTROL_CMD_CONFVALUE:
    case CONTROL_CMD_EVENT:
    case CONTROL_CMD_INFOVALUE:
      log_fn(LOG_WARN, "Received client-only '%s' command; ignoring.",
             control_cmd_to_string(command_type));
      send_control_error(conn, ERR_UNRECOGNIZED_TYPE,
                         "Command type only valid from server to tor client");
      break;
    case CONTROL_CMD_FRAGMENTHEADER:
    case CONTROL_CMD_FRAGMENT:
      log_fn(LOG_WARN, "Recieved command fragment out of order; ignoring.");
      send_control_error(conn, ERR_SYNTAX, "Bad fragmentation on command.");
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

/** Something has happened to circuit <b>circ</b>: tell any interested
 * control connections. */
int
control_event_circuit_status(circuit_t *circ, circuit_status_event_t tp)
{
  char *path, *msg;
  size_t path_len;
  if (!EVENT_IS_INTERESTING(EVENT_CIRCUIT_STATUS))
    return 0;
  tor_assert(circ);
  tor_assert(CIRCUIT_IS_ORIGIN(circ));

  path = circuit_list_path(circ,0);
  path_len = strlen(path);
  msg = tor_malloc(1+4+path_len+1); /* event, circid, path, NUL. */
  msg[0] = (uint8_t) tp;
  set_uint32(msg+1, htonl(circ->global_identifier));
  strlcpy(msg+5,path,path_len+1);

  send_control_event(EVENT_CIRCUIT_STATUS, (uint32_t)(path_len+6), msg);
  tor_free(path);
  tor_free(msg);
  return 0;
}

/** Something has happened to the stream associated with AP connection
 * <b>conn</b>: tell any interested control connections. */
int
control_event_stream_status(connection_t *conn, stream_status_event_t tp)
{
  char *msg;
  size_t len;
  char buf[256], buf2[256];
  tor_assert(conn->type == CONN_TYPE_AP);
  tor_assert(conn->socks_request);

  if (!EVENT_IS_INTERESTING(EVENT_STREAM_STATUS))
    return 0;

  if (conn->chosen_exit_name)
    tor_snprintf(buf2, sizeof(buf2), ".%s.exit", conn->chosen_exit_name);
  tor_snprintf(buf, sizeof(buf), "%s%s:%d",
               conn->socks_request->address,
               conn->chosen_exit_name ? buf2 : "",
               conn->socks_request->port),
  len = strlen(buf);
  msg = tor_malloc(5+len+1);
  msg[0] = (uint8_t) tp;
  set_uint32(msg+1, htonl(conn->global_identifier));
  strlcpy(msg+5, buf, len+1);

  send_control_event(EVENT_STREAM_STATUS, (uint32_t)(5+len+1), msg);
  tor_free(msg);
  return 0;
}

/** Something has happened to the OR connection <b>conn</b>: tell any
 * interested control connections. */
int
control_event_or_conn_status(connection_t *conn,or_conn_status_event_t tp)
{
  char buf[HEX_DIGEST_LEN+3]; /* status, dollar, identity, NUL */
  size_t len;

  tor_assert(conn->type == CONN_TYPE_OR);

  if (!EVENT_IS_INTERESTING(EVENT_OR_CONN_STATUS))
    return 0;

  buf[0] = (uint8_t)tp;
  strlcpy(buf+1,conn->nickname,sizeof(buf)-1);
  len = strlen(buf+1);
  send_control_event(EVENT_OR_CONN_STATUS, (uint32_t)(len+1), buf);
  return 0;
}

/** A second or more has elapsed: tell any interested control
 * connections how much bandwidth we used. */
int
control_event_bandwidth_used(uint32_t n_read, uint32_t n_written)
{
  char buf[8];

  if (!EVENT_IS_INTERESTING(EVENT_BANDWIDTH_USED))
    return 0;

  set_uint32(buf, htonl(n_read));
  set_uint32(buf+4, htonl(n_written));
  send_control_event(EVENT_BANDWIDTH_USED, 8, buf);

  return 0;
}

/** We got a log message: tell any interested control connections. */
void
control_event_logmsg(int severity, const char *msg)
{
  static int sending_logmsg=0;
  int oldlog, event;

  if (sending_logmsg)
    return;

  oldlog = EVENT_IS_INTERESTING(EVENT_LOG_OBSOLETE) &&
    (severity == LOG_NOTICE || severity == LOG_WARN || severity == LOG_ERR);
  event = log_severity_to_event(severity);

  if (event<0 || !EVENT_IS_INTERESTING(event))
    event = 0;

  if (oldlog || event) {
    size_t len = strlen(msg);
    sending_logmsg = 1;
    if (event)
      send_control_event(event, (uint32_t)(len+1), msg);
    if (oldlog)
      send_control_event(EVENT_LOG_OBSOLETE, (uint32_t)(len+1), msg);
    sending_logmsg = 0;
  }
}

/** Called whenever we receive new router descriptors: tell any
 * interested control connections.  <b>routers</b> is a list of
 * DIGEST_LEN-byte identity digests.
 */
int control_event_descriptors_changed(smartlist_t *routers)
{
  size_t len;
  char *msg;
  smartlist_t *identities;
  char buf[HEX_DIGEST_LEN+1];

  if (!EVENT_IS_INTERESTING(EVENT_NEW_DESC))
    return 0;
  identities = smartlist_create();
  SMARTLIST_FOREACH(routers, routerinfo_t *, r,
  {
    base16_encode(buf,sizeof(buf),r->identity_digest,DIGEST_LEN);
    smartlist_add(identities, tor_strdup(buf));
  });
  msg = smartlist_join_strings(identities, ",", 1, &len);
  send_control_event(EVENT_NEW_DESC, len+1, msg);

  SMARTLIST_FOREACH(identities, char *, cp, tor_free(cp));
  smartlist_free(identities);
  tor_free(msg);
  return 0;
}

/** Choose a random authentication cookie and write it to disk.
 * Anybody who can read the cookie from disk will be considered
 * authorized to use the control connection. */
int
init_cookie_authentication(int enabled)
{
  char fname[512];

  if (!enabled) {
    authentication_cookie_is_set = 0;
    return 0;
  }

  tor_snprintf(fname, sizeof(fname), "%s/control_auth_cookie",
               get_options()->DataDirectory);
  crypto_rand(authentication_cookie, AUTHENTICATION_COOKIE_LEN);
  authentication_cookie_is_set = 1;
  if (write_bytes_to_file(fname, authentication_cookie,
                          AUTHENTICATION_COOKIE_LEN, 1)) {
    log_fn(LOG_WARN,"Error writing authentication cookie.");
    return -1;
  }

  return 0;
}
