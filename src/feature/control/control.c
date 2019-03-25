/* Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2019, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file control.c
 * \brief Implementation for Tor's control-socket interface.
 *
 * A "controller" is an external program that monitors and controls a Tor
 * instance via a text-based protocol. It connects to Tor via a connection
 * to a local socket.
 *
 * The protocol is line-driven.  The controller sends commands terminated by a
 * CRLF.  Tor sends lines that are either <em>replies</em> to what the
 * controller has said, or <em>events</em> that Tor sends to the controller
 * asynchronously based on occurrences in the Tor network model.
 *
 * See the control-spec.txt file in the torspec.git repository for full
 * details on protocol.
 *
 * This module generally has two kinds of entry points: those based on having
 * received a command on a controller socket, which are handled in
 * connection_control_process_inbuf(), and dispatched to individual functions
 * with names like control_handle_COMMANDNAME(); and those based on events
 * that occur elsewhere in Tor, which are handled by functions with names like
 * control_event_EVENTTYPE().
 *
 * Controller events are not sent immediately; rather, they are inserted into
 * the queued_control_events array, and flushed later from
 * flush_queued_events_cb().  Doing this simplifies our callgraph greatly,
 * by limiting the number of places in Tor that can call back into the network
 * stack.
 **/

#define CONTROL_MODULE_PRIVATE
#define CONTROL_PRIVATE
#define CONTROL_EVENTS_PRIVATE
#define OCIRC_EVENT_PRIVATE

#include "core/or/or.h"
#include "app/config/config.h"
#include "app/config/confparse.h"
#include "app/main/main.h"
#include "core/mainloop/connection.h"
#include "core/mainloop/mainloop.h"
#include "core/or/channel.h"
#include "core/or/channeltls.h"
#include "core/or/circuitbuild.h"
#include "core/or/circuitlist.h"
#include "core/or/circuitstats.h"
#include "core/or/circuituse.h"
#include "core/or/command.h"
#include "core/or/connection_edge.h"
#include "core/or/connection_or.h"
#include "core/or/ocirc_event.h"
#include "core/or/policies.h"
#include "core/or/reasons.h"
#include "core/or/versions.h"
#include "core/proto/proto_control0.h"
#include "core/proto/proto_http.h"
#include "feature/client/addressmap.h"
#include "feature/client/bridges.h"
#include "feature/client/dnsserv.h"
#include "feature/client/entrynodes.h"
#include "feature/control/control.h"
#include "feature/control/control_events.h"
#include "feature/control/control_fmt.h"
#include "feature/control/control_getinfo.h"
#include "feature/control/fmt_serverstatus.h"
#include "feature/control/getinfo_geoip.h"
#include "feature/dircache/dirserv.h"
#include "feature/dirclient/dirclient.h"
#include "feature/dirclient/dlstatus.h"
#include "feature/dircommon/directory.h"
#include "feature/hibernate/hibernate.h"
#include "feature/hs/hs_cache.h"
#include "feature/hs/hs_common.h"
#include "feature/hs/hs_control.h"
#include "feature/hs_common/shared_random_client.h"
#include "feature/nodelist/authcert.h"
#include "feature/nodelist/dirlist.h"
#include "feature/nodelist/microdesc.h"
#include "feature/nodelist/networkstatus.h"
#include "feature/nodelist/nodelist.h"
#include "feature/nodelist/routerinfo.h"
#include "feature/nodelist/routerlist.h"
#include "feature/relay/router.h"
#include "feature/relay/routermode.h"
#include "feature/relay/selftest.h"
#include "feature/rend/rendclient.h"
#include "feature/rend/rendcommon.h"
#include "feature/rend/rendparse.h"
#include "feature/rend/rendservice.h"
#include "feature/stats/geoip_stats.h"
#include "feature/stats/predict_ports.h"
#include "lib/buf/buffers.h"
#include "lib/crypt_ops/crypto_rand.h"
#include "lib/crypt_ops/crypto_util.h"
#include "lib/encoding/confline.h"
#include "lib/evloop/compat_libevent.h"
#include "lib/version/torversion.h"

#include "feature/dircache/cached_dir_st.h"
#include "feature/control/control_connection_st.h"
#include "core/or/cpath_build_state_st.h"
#include "core/or/entry_connection_st.h"
#include "feature/nodelist/extrainfo_st.h"
#include "feature/nodelist/networkstatus_st.h"
#include "feature/nodelist/node_st.h"
#include "core/or/or_connection_st.h"
#include "core/or/or_circuit_st.h"
#include "core/or/origin_circuit_st.h"
#include "feature/nodelist/microdesc_st.h"
#include "feature/rend/rend_authorized_client_st.h"
#include "feature/rend/rend_encoded_v2_service_descriptor_st.h"
#include "feature/rend/rend_service_descriptor_st.h"
#include "feature/nodelist/routerinfo_st.h"
#include "feature/nodelist/routerlist_st.h"
#include "core/or/socks_request_st.h"

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#ifndef _WIN32
#include <pwd.h>
#include <sys/resource.h>
#endif

#include "lib/crypt_ops/crypto_s2k.h"
#include "lib/evloop/procmon.h"
#include "lib/evloop/compat_libevent.h"

/** Yield true iff <b>s</b> is the state of a control_connection_t that has
 * finished authentication and is accepting commands. */
#define STATE_IS_OPEN(s) ((s) == CONTROL_CONN_STATE_OPEN)

/** If we're using cookie-type authentication, how long should our cookies be?
 */
#define AUTHENTICATION_COOKIE_LEN 32

/** If true, we've set authentication_cookie to a secret code and
 * stored it to disk. */
static int authentication_cookie_is_set = 0;
/** If authentication_cookie_is_set, a secret cookie that we've stored to disk
 * and which we're using to authenticate controllers.  (If the controller can
 * read it off disk, it has permission to connect.) */
static uint8_t *authentication_cookie = NULL;

#define SAFECOOKIE_SERVER_TO_CONTROLLER_CONSTANT \
  "Tor safe cookie authentication server-to-controller hash"
#define SAFECOOKIE_CONTROLLER_TO_SERVER_CONSTANT \
  "Tor safe cookie authentication controller-to-server hash"
#define SAFECOOKIE_SERVER_NONCE_LEN DIGEST256_LEN

/** The list of onion services that have been added via ADD_ONION that do not
 * belong to any particular control connection.
 */
static smartlist_t *detached_onion_services = NULL;

static void send_control_done(control_connection_t *conn);
static int handle_control_setconf(control_connection_t *conn, uint32_t len,
                                  char *body);
static int handle_control_resetconf(control_connection_t *conn, uint32_t len,
                                    char *body);
static int handle_control_getconf(control_connection_t *conn, uint32_t len,
                                  const char *body);
static int handle_control_loadconf(control_connection_t *conn, uint32_t len,
                                  const char *body);
static int handle_control_setevents(control_connection_t *conn, uint32_t len,
                                    const char *body);
static int handle_control_authenticate(control_connection_t *conn,
                                       uint32_t len,
                                       const char *body);
static int handle_control_signal(control_connection_t *conn, uint32_t len,
                                 const char *body);
static int handle_control_mapaddress(control_connection_t *conn, uint32_t len,
                                     const char *body);
static int handle_control_extendcircuit(control_connection_t *conn,
                                        uint32_t len,
                                        const char *body);
static int handle_control_setcircuitpurpose(control_connection_t *conn,
                                            uint32_t len, const char *body);
static int handle_control_attachstream(control_connection_t *conn,
                                       uint32_t len,
                                        const char *body);
static int handle_control_postdescriptor(control_connection_t *conn,
                                         uint32_t len,
                                         const char *body);
static int handle_control_redirectstream(control_connection_t *conn,
                                         uint32_t len,
                                         const char *body);
static int handle_control_closestream(control_connection_t *conn, uint32_t len,
                                      const char *body);
static int handle_control_closecircuit(control_connection_t *conn,
                                       uint32_t len,
                                       const char *body);
static int handle_control_resolve(control_connection_t *conn, uint32_t len,
                                  const char *body);
static int handle_control_usefeature(control_connection_t *conn,
                                     uint32_t len,
                                     const char *body);
static int handle_control_hsfetch(control_connection_t *conn, uint32_t len,
                                  const char *body);
static int handle_control_hspost(control_connection_t *conn, uint32_t len,
                                 const char *body);
static int handle_control_add_onion(control_connection_t *conn, uint32_t len,
                                    const char *body);
static int handle_control_del_onion(control_connection_t *conn, uint32_t len,
                                    const char *body);

/** Convert a connection_t* to an control_connection_t*; assert if the cast is
 * invalid. */
control_connection_t *
TO_CONTROL_CONN(connection_t *c)
{
  tor_assert(c->magic == CONTROL_CONNECTION_MAGIC);
  return DOWNCAST(control_connection_t, c);
}

/** If the first <b>in_len_max</b> characters in <b>start</b> contain a
 * double-quoted string with escaped characters, return the length of that
 * string (as encoded, including quotes).  Otherwise return -1. */
static inline int
get_escaped_string_length(const char *start, size_t in_len_max,
                          int *chars_out)
{
  const char *cp, *end;
  int chars = 0;

  if (*start != '\"')
    return -1;

  cp = start+1;
  end = start+in_len_max;

  /* Calculate length. */
  while (1) {
    if (cp >= end) {
      return -1; /* Too long. */
    } else if (*cp == '\\') {
      if (++cp == end)
        return -1; /* Can't escape EOS. */
      ++cp;
      ++chars;
    } else if (*cp == '\"') {
      break;
    } else {
      ++cp;
      ++chars;
    }
  }
  if (chars_out)
    *chars_out = chars;
  return (int)(cp - start+1);
}

/** As decode_escaped_string, but does not decode the string: copies the
 * entire thing, including quotation marks. */
static const char *
extract_escaped_string(const char *start, size_t in_len_max,
                       char **out, size_t *out_len)
{
  int length = get_escaped_string_length(start, in_len_max, NULL);
  if (length<0)
    return NULL;
  *out_len = length;
  *out = tor_strndup(start, *out_len);
  return start+length;
}

/** Given a pointer to a string starting at <b>start</b> containing
 * <b>in_len_max</b> characters, decode a string beginning with one double
 * quote, containing any number of non-quote characters or characters escaped
 * with a backslash, and ending with a final double quote.  Place the resulting
 * string (unquoted, unescaped) into a newly allocated string in *<b>out</b>;
 * store its length in <b>out_len</b>.  On success, return a pointer to the
 * character immediately following the escaped string.  On failure, return
 * NULL. */
static const char *
decode_escaped_string(const char *start, size_t in_len_max,
                   char **out, size_t *out_len)
{
  const char *cp, *end;
  char *outp;
  int len, n_chars = 0;

  len = get_escaped_string_length(start, in_len_max, &n_chars);
  if (len<0)
    return NULL;

  end = start+len-1; /* Index of last quote. */
  tor_assert(*end == '\"');
  outp = *out = tor_malloc(len+1);
  *out_len = n_chars;

  cp = start+1;
  while (cp < end) {
    if (*cp == '\\')
      ++cp;
    *outp++ = *cp++;
  }
  *outp = '\0';
  tor_assert((outp - *out) == (int)*out_len);

  return end+1;
}

/** Create and add a new controller connection on <b>sock</b>.  If
 * <b>CC_LOCAL_FD_IS_OWNER</b> is set in <b>flags</b>, this Tor process should
 * exit when the connection closes.  If <b>CC_LOCAL_FD_IS_AUTHENTICATED</b>
 * is set, then the connection does not need to authenticate.
 */
int
control_connection_add_local_fd(tor_socket_t sock, unsigned flags)
{
  if (BUG(! SOCKET_OK(sock)))
    return -1;
  const int is_owner = !!(flags & CC_LOCAL_FD_IS_OWNER);
  const int is_authenticated = !!(flags & CC_LOCAL_FD_IS_AUTHENTICATED);
  control_connection_t *control_conn = control_connection_new(AF_UNSPEC);
  connection_t *conn = TO_CONN(control_conn);
  conn->s = sock;
  tor_addr_make_unspec(&conn->addr);
  conn->port = 1;
  conn->address = tor_strdup("<local socket>");

  /* We take ownership of this socket so that later, when we close it,
   * we don't freak out. */
  tor_take_socket_ownership(sock);

  if (set_socket_nonblocking(sock) < 0 ||
      connection_add(conn) < 0) {
    connection_free(conn);
    return -1;
  }

  control_conn->is_owning_control_connection = is_owner;

  if (connection_init_accepted_conn(conn, NULL) < 0) {
    connection_mark_for_close(conn);
    return -1;
  }

  if (is_authenticated) {
    conn->state = CONTROL_CONN_STATE_OPEN;
  }

  return 0;
}

/** Write all of the open control ports to ControlPortWriteToFile */
void
control_ports_write_to_file(void)
{
  smartlist_t *lines;
  char *joined = NULL;
  const or_options_t *options = get_options();

  if (!options->ControlPortWriteToFile)
    return;

  lines = smartlist_new();

  SMARTLIST_FOREACH_BEGIN(get_connection_array(), const connection_t *, conn) {
    if (conn->type != CONN_TYPE_CONTROL_LISTENER || conn->marked_for_close)
      continue;
#ifdef AF_UNIX
    if (conn->socket_family == AF_UNIX) {
      smartlist_add_asprintf(lines, "UNIX_PORT=%s\n", conn->address);
      continue;
    }
#endif /* defined(AF_UNIX) */
    smartlist_add_asprintf(lines, "PORT=%s:%d\n", conn->address, conn->port);
  } SMARTLIST_FOREACH_END(conn);

  joined = smartlist_join_strings(lines, "", 0, NULL);

  if (write_str_to_file(options->ControlPortWriteToFile, joined, 0) < 0) {
    log_warn(LD_CONTROL, "Writing %s failed: %s",
             options->ControlPortWriteToFile, strerror(errno));
  }
#ifndef _WIN32
  if (options->ControlPortFileGroupReadable) {
    if (chmod(options->ControlPortWriteToFile, 0640)) {
      log_warn(LD_FS,"Unable to make %s group-readable.",
               options->ControlPortWriteToFile);
    }
  }
#endif /* !defined(_WIN32) */
  tor_free(joined);
  SMARTLIST_FOREACH(lines, char *, cp, tor_free(cp));
  smartlist_free(lines);
}

/** Send a "DONE" message down the control connection <b>conn</b>. */
static void
send_control_done(control_connection_t *conn)
{
  connection_write_str_to_buf("250 OK\r\n", conn);
}

/** Given a text circuit <b>id</b>, return the corresponding circuit. */
static origin_circuit_t *
get_circ(const char *id)
{
  uint32_t n_id;
  int ok;
  n_id = (uint32_t) tor_parse_ulong(id, 10, 0, UINT32_MAX, &ok, NULL);
  if (!ok)
    return NULL;
  return circuit_get_by_global_id(n_id);
}

/** Given a text stream <b>id</b>, return the corresponding AP connection. */
static entry_connection_t *
get_stream(const char *id)
{
  uint64_t n_id;
  int ok;
  connection_t *conn;
  n_id = tor_parse_uint64(id, 10, 0, UINT64_MAX, &ok, NULL);
  if (!ok)
    return NULL;
  conn = connection_get_by_global_id(n_id);
  if (!conn || conn->type != CONN_TYPE_AP || conn->marked_for_close)
    return NULL;
  return TO_ENTRY_CONN(conn);
}

/** Helper for setconf and resetconf. Acts like setconf, except
 * it passes <b>use_defaults</b> on to options_trial_assign().  Modifies the
 * contents of body.
 */
static int
control_setconf_helper(control_connection_t *conn, uint32_t len, char *body,
                       int use_defaults)
{
  setopt_err_t opt_err;
  config_line_t *lines=NULL;
  char *start = body;
  char *errstring = NULL;
  const unsigned flags =
    CAL_CLEAR_FIRST | (use_defaults ? CAL_USE_DEFAULTS : 0);

  char *config;
  smartlist_t *entries = smartlist_new();

  /* We have a string, "body", of the format '(key(=val|="val")?)' entries
   * separated by space.  break it into a list of configuration entries. */
  while (*body) {
    char *eq = body;
    char *key;
    char *entry;
    while (!TOR_ISSPACE(*eq) && *eq != '=')
      ++eq;
    key = tor_strndup(body, eq-body);
    body = eq+1;
    if (*eq == '=') {
      char *val=NULL;
      size_t val_len=0;
      if (*body != '\"') {
        char *val_start = body;
        while (!TOR_ISSPACE(*body))
          body++;
        val = tor_strndup(val_start, body-val_start);
        val_len = strlen(val);
      } else {
        body = (char*)extract_escaped_string(body, (len - (body-start)),
                                             &val, &val_len);
        if (!body) {
          connection_write_str_to_buf("551 Couldn't parse string\r\n", conn);
          SMARTLIST_FOREACH(entries, char *, cp, tor_free(cp));
          smartlist_free(entries);
          tor_free(key);
          return 0;
        }
      }
      tor_asprintf(&entry, "%s %s", key, val);
      tor_free(key);
      tor_free(val);
    } else {
      entry = key;
    }
    smartlist_add(entries, entry);
    while (TOR_ISSPACE(*body))
      ++body;
  }

  smartlist_add_strdup(entries, "");
  config = smartlist_join_strings(entries, "\n", 0, NULL);
  SMARTLIST_FOREACH(entries, char *, cp, tor_free(cp));
  smartlist_free(entries);

  if (config_get_lines(config, &lines, 0) < 0) {
    log_warn(LD_CONTROL,"Controller gave us config lines we can't parse.");
    connection_write_str_to_buf("551 Couldn't parse configuration\r\n",
                                conn);
    tor_free(config);
    return 0;
  }
  tor_free(config);

  opt_err = options_trial_assign(lines, flags, &errstring);
  {
    const char *msg;
    switch (opt_err) {
      case SETOPT_ERR_MISC:
        msg = "552 Unrecognized option";
        break;
      case SETOPT_ERR_PARSE:
        msg = "513 Unacceptable option value";
        break;
      case SETOPT_ERR_TRANSITION:
        msg = "553 Transition not allowed";
        break;
      case SETOPT_ERR_SETTING:
      default:
        msg = "553 Unable to set option";
        break;
      case SETOPT_OK:
        config_free_lines(lines);
        send_control_done(conn);
        return 0;
    }
    log_warn(LD_CONTROL,
             "Controller gave us config lines that didn't validate: %s",
             errstring);
    connection_printf_to_buf(conn, "%s: %s\r\n", msg, errstring);
    config_free_lines(lines);
    tor_free(errstring);
    return 0;
  }
}

/** Called when we receive a SETCONF message: parse the body and try
 * to update our configuration.  Reply with a DONE or ERROR message.
 * Modifies the contents of body.*/
static int
handle_control_setconf(control_connection_t *conn, uint32_t len, char *body)
{
  return control_setconf_helper(conn, len, body, 0);
}

/** Called when we receive a RESETCONF message: parse the body and try
 * to update our configuration.  Reply with a DONE or ERROR message.
 * Modifies the contents of body. */
static int
handle_control_resetconf(control_connection_t *conn, uint32_t len, char *body)
{
  return control_setconf_helper(conn, len, body, 1);
}

/** Called when we receive a GETCONF message.  Parse the request, and
 * reply with a CONFVALUE or an ERROR message */
static int
handle_control_getconf(control_connection_t *conn, uint32_t body_len,
                       const char *body)
{
  smartlist_t *questions = smartlist_new();
  smartlist_t *answers = smartlist_new();
  smartlist_t *unrecognized = smartlist_new();
  char *msg = NULL;
  size_t msg_len;
  const or_options_t *options = get_options();
  int i, len;

  (void) body_len; /* body is NUL-terminated; so we can ignore len. */
  smartlist_split_string(questions, body, " ",
                         SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 0);
  SMARTLIST_FOREACH_BEGIN(questions, const char *, q) {
    if (!option_is_recognized(q)) {
      smartlist_add(unrecognized, (char*) q);
    } else {
      config_line_t *answer = option_get_assignment(options,q);
      if (!answer) {
        const char *name = option_get_canonical_name(q);
        smartlist_add_asprintf(answers, "250-%s\r\n", name);
      }

      while (answer) {
        config_line_t *next;
        smartlist_add_asprintf(answers, "250-%s=%s\r\n",
                     answer->key, answer->value);

        next = answer->next;
        tor_free(answer->key);
        tor_free(answer->value);
        tor_free(answer);
        answer = next;
      }
    }
  } SMARTLIST_FOREACH_END(q);

  if ((len = smartlist_len(unrecognized))) {
    for (i=0; i < len-1; ++i)
      connection_printf_to_buf(conn,
                               "552-Unrecognized configuration key \"%s\"\r\n",
                               (char*)smartlist_get(unrecognized, i));
    connection_printf_to_buf(conn,
                             "552 Unrecognized configuration key \"%s\"\r\n",
                             (char*)smartlist_get(unrecognized, len-1));
  } else if ((len = smartlist_len(answers))) {
    char *tmp = smartlist_get(answers, len-1);
    tor_assert(strlen(tmp)>4);
    tmp[3] = ' ';
    msg = smartlist_join_strings(answers, "", 0, &msg_len);
    connection_buf_add(msg, msg_len, TO_CONN(conn));
  } else {
    connection_write_str_to_buf("250 OK\r\n", conn);
  }

  SMARTLIST_FOREACH(answers, char *, cp, tor_free(cp));
  smartlist_free(answers);
  SMARTLIST_FOREACH(questions, char *, cp, tor_free(cp));
  smartlist_free(questions);
  smartlist_free(unrecognized);

  tor_free(msg);

  return 0;
}

/** Called when we get a +LOADCONF message. */
static int
handle_control_loadconf(control_connection_t *conn, uint32_t len,
                         const char *body)
{
  setopt_err_t retval;
  char *errstring = NULL;
  const char *msg = NULL;
  (void) len;

  retval = options_init_from_string(NULL, body, CMD_RUN_TOR, NULL, &errstring);

  if (retval != SETOPT_OK)
    log_warn(LD_CONTROL,
             "Controller gave us config file that didn't validate: %s",
             errstring);

  switch (retval) {
  case SETOPT_ERR_PARSE:
    msg = "552 Invalid config file";
    break;
  case SETOPT_ERR_TRANSITION:
    msg = "553 Transition not allowed";
    break;
  case SETOPT_ERR_SETTING:
    msg = "553 Unable to set option";
    break;
  case SETOPT_ERR_MISC:
  default:
    msg = "550 Unable to load config";
    break;
  case SETOPT_OK:
    break;
  }
  if (msg) {
    if (errstring)
      connection_printf_to_buf(conn, "%s: %s\r\n", msg, errstring);
    else
      connection_printf_to_buf(conn, "%s\r\n", msg);
  } else {
    send_control_done(conn);
  }
  tor_free(errstring);
  return 0;
}

/** Called when we get a SETEVENTS message: update conn->event_mask,
 * and reply with DONE or ERROR. */
static int
handle_control_setevents(control_connection_t *conn, uint32_t len,
                         const char *body)
{
  int event_code;
  event_mask_t event_mask = 0;
  smartlist_t *events = smartlist_new();

  (void) len;

  smartlist_split_string(events, body, " ",
                         SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 0);
  SMARTLIST_FOREACH_BEGIN(events, const char *, ev)
    {
      if (!strcasecmp(ev, "EXTENDED") ||
          !strcasecmp(ev, "AUTHDIR_NEWDESCS")) {
        log_warn(LD_CONTROL, "The \"%s\" SETEVENTS argument is no longer "
                 "supported.", ev);
        continue;
      } else {
        int i;
        event_code = -1;

        for (i = 0; control_event_table[i].event_name != NULL; ++i) {
          if (!strcasecmp(ev, control_event_table[i].event_name)) {
            event_code = control_event_table[i].event_code;
            break;
          }
        }

        if (event_code == -1) {
          connection_printf_to_buf(conn, "552 Unrecognized event \"%s\"\r\n",
                                   ev);
          SMARTLIST_FOREACH(events, char *, e, tor_free(e));
          smartlist_free(events);
          return 0;
        }
      }
      event_mask |= (((event_mask_t)1) << event_code);
    }
  SMARTLIST_FOREACH_END(ev);
  SMARTLIST_FOREACH(events, char *, e, tor_free(e));
  smartlist_free(events);

  conn->event_mask = event_mask;

  control_update_global_event_mask();
  send_control_done(conn);
  return 0;
}

/** Decode the hashed, base64'd passwords stored in <b>passwords</b>.
 * Return a smartlist of acceptable passwords (unterminated strings of
 * length S2K_RFC2440_SPECIFIER_LEN+DIGEST_LEN) on success, or NULL on
 * failure.
 */
smartlist_t *
decode_hashed_passwords(config_line_t *passwords)
{
  char decoded[64];
  config_line_t *cl;
  smartlist_t *sl = smartlist_new();

  tor_assert(passwords);

  for (cl = passwords; cl; cl = cl->next) {
    const char *hashed = cl->value;

    if (!strcmpstart(hashed, "16:")) {
      if (base16_decode(decoded, sizeof(decoded), hashed+3, strlen(hashed+3))
                        != S2K_RFC2440_SPECIFIER_LEN + DIGEST_LEN
          || strlen(hashed+3) != (S2K_RFC2440_SPECIFIER_LEN+DIGEST_LEN)*2) {
        goto err;
      }
    } else {
        if (base64_decode(decoded, sizeof(decoded), hashed, strlen(hashed))
            != S2K_RFC2440_SPECIFIER_LEN+DIGEST_LEN) {
          goto err;
        }
    }
    smartlist_add(sl,
                  tor_memdup(decoded, S2K_RFC2440_SPECIFIER_LEN+DIGEST_LEN));
  }

  return sl;

 err:
  SMARTLIST_FOREACH(sl, char*, cp, tor_free(cp));
  smartlist_free(sl);
  return NULL;
}

/** Called when we get an AUTHENTICATE message.  Check whether the
 * authentication is valid, and if so, update the connection's state to
 * OPEN.  Reply with DONE or ERROR.
 */
static int
handle_control_authenticate(control_connection_t *conn, uint32_t len,
                            const char *body)
{
  int used_quoted_string = 0;
  const or_options_t *options = get_options();
  const char *errstr = "Unknown error";
  char *password;
  size_t password_len;
  const char *cp;
  int i;
  int bad_cookie=0, bad_password=0;
  smartlist_t *sl = NULL;

  if (!len) {
    password = tor_strdup("");
    password_len = 0;
  } else if (TOR_ISXDIGIT(body[0])) {
    cp = body;
    while (TOR_ISXDIGIT(*cp))
      ++cp;
    i = (int)(cp - body);
    tor_assert(i>0);
    password_len = i/2;
    password = tor_malloc(password_len + 1);
    if (base16_decode(password, password_len+1, body, i)
                      != (int) password_len) {
      connection_write_str_to_buf(
            "551 Invalid hexadecimal encoding.  Maybe you tried a plain text "
            "password?  If so, the standard requires that you put it in "
            "double quotes.\r\n", conn);
      connection_mark_for_close(TO_CONN(conn));
      tor_free(password);
      return 0;
    }
  } else {
    if (!decode_escaped_string(body, len, &password, &password_len)) {
      connection_write_str_to_buf("551 Invalid quoted string.  You need "
            "to put the password in double quotes.\r\n", conn);
      connection_mark_for_close(TO_CONN(conn));
      return 0;
    }
    used_quoted_string = 1;
  }

  if (conn->safecookie_client_hash != NULL) {
    /* The controller has chosen safe cookie authentication; the only
     * acceptable authentication value is the controller-to-server
     * response. */

    tor_assert(authentication_cookie_is_set);

    if (password_len != DIGEST256_LEN) {
      log_warn(LD_CONTROL,
               "Got safe cookie authentication response with wrong length "
               "(%d)", (int)password_len);
      errstr = "Wrong length for safe cookie response.";
      goto err;
    }

    if (tor_memneq(conn->safecookie_client_hash, password, DIGEST256_LEN)) {
      log_warn(LD_CONTROL,
               "Got incorrect safe cookie authentication response");
      errstr = "Safe cookie response did not match expected value.";
      goto err;
    }

    tor_free(conn->safecookie_client_hash);
    goto ok;
  }

  if (!options->CookieAuthentication && !options->HashedControlPassword &&
      !options->HashedControlSessionPassword) {
    /* if Tor doesn't demand any stronger authentication, then
     * the controller can get in with anything. */
    goto ok;
  }

  if (options->CookieAuthentication) {
    int also_password = options->HashedControlPassword != NULL ||
      options->HashedControlSessionPassword != NULL;
    if (password_len != AUTHENTICATION_COOKIE_LEN) {
      if (!also_password) {
        log_warn(LD_CONTROL, "Got authentication cookie with wrong length "
                 "(%d)", (int)password_len);
        errstr = "Wrong length on authentication cookie.";
        goto err;
      }
      bad_cookie = 1;
    } else if (tor_memneq(authentication_cookie, password, password_len)) {
      if (!also_password) {
        log_warn(LD_CONTROL, "Got mismatched authentication cookie");
        errstr = "Authentication cookie did not match expected value.";
        goto err;
      }
      bad_cookie = 1;
    } else {
      goto ok;
    }
  }

  if (options->HashedControlPassword ||
      options->HashedControlSessionPassword) {
    int bad = 0;
    smartlist_t *sl_tmp;
    char received[DIGEST_LEN];
    int also_cookie = options->CookieAuthentication;
    sl = smartlist_new();
    if (options->HashedControlPassword) {
      sl_tmp = decode_hashed_passwords(options->HashedControlPassword);
      if (!sl_tmp)
        bad = 1;
      else {
        smartlist_add_all(sl, sl_tmp);
        smartlist_free(sl_tmp);
      }
    }
    if (options->HashedControlSessionPassword) {
      sl_tmp = decode_hashed_passwords(options->HashedControlSessionPassword);
      if (!sl_tmp)
        bad = 1;
      else {
        smartlist_add_all(sl, sl_tmp);
        smartlist_free(sl_tmp);
      }
    }
    if (bad) {
      if (!also_cookie) {
        log_warn(LD_BUG,
                 "Couldn't decode HashedControlPassword: invalid base16");
        errstr="Couldn't decode HashedControlPassword value in configuration.";
        goto err;
      }
      bad_password = 1;
      SMARTLIST_FOREACH(sl, char *, str, tor_free(str));
      smartlist_free(sl);
      sl = NULL;
    } else {
      SMARTLIST_FOREACH(sl, char *, expected,
      {
        secret_to_key_rfc2440(received,DIGEST_LEN,
                              password,password_len,expected);
        if (tor_memeq(expected + S2K_RFC2440_SPECIFIER_LEN,
                      received, DIGEST_LEN))
          goto ok;
      });
      SMARTLIST_FOREACH(sl, char *, str, tor_free(str));
      smartlist_free(sl);
      sl = NULL;

      if (used_quoted_string)
        errstr = "Password did not match HashedControlPassword value from "
          "configuration";
      else
        errstr = "Password did not match HashedControlPassword value from "
          "configuration. Maybe you tried a plain text password? "
          "If so, the standard requires that you put it in double quotes.";
      bad_password = 1;
      if (!also_cookie)
        goto err;
    }
  }

  /** We only get here if both kinds of authentication failed. */
  tor_assert(bad_password && bad_cookie);
  log_warn(LD_CONTROL, "Bad password or authentication cookie on controller.");
  errstr = "Password did not match HashedControlPassword *or* authentication "
    "cookie.";

 err:
  tor_free(password);
  connection_printf_to_buf(conn, "515 Authentication failed: %s\r\n", errstr);
  connection_mark_for_close(TO_CONN(conn));
  if (sl) { /* clean up */
    SMARTLIST_FOREACH(sl, char *, str, tor_free(str));
    smartlist_free(sl);
  }
  return 0;
 ok:
  log_info(LD_CONTROL, "Authenticated control connection ("TOR_SOCKET_T_FORMAT
           ")", conn->base_.s);
  send_control_done(conn);
  conn->base_.state = CONTROL_CONN_STATE_OPEN;
  tor_free(password);
  if (sl) { /* clean up */
    SMARTLIST_FOREACH(sl, char *, str, tor_free(str));
    smartlist_free(sl);
  }
  return 0;
}

/** Called when we get a SAVECONF command. Try to flush the current options to
 * disk, and report success or failure. */
static int
handle_control_saveconf(control_connection_t *conn, uint32_t len,
                        const char *body)
{
  (void) len;

  int force = !strcmpstart(body, "FORCE");
  const or_options_t *options = get_options();
  if ((!force && options->IncludeUsed) || options_save_current() < 0) {
    connection_write_str_to_buf(
      "551 Unable to write configuration to disk.\r\n", conn);
  } else {
    send_control_done(conn);
  }
  return 0;
}

const struct signal_name_t signal_table[] = {
  { SIGHUP, "RELOAD" },
  { SIGHUP, "HUP" },
  { SIGINT, "SHUTDOWN" },
  { SIGUSR1, "DUMP" },
  { SIGUSR1, "USR1" },
  { SIGUSR2, "DEBUG" },
  { SIGUSR2, "USR2" },
  { SIGTERM, "HALT" },
  { SIGTERM, "TERM" },
  { SIGTERM, "INT" },
  { SIGNEWNYM, "NEWNYM" },
  { SIGCLEARDNSCACHE, "CLEARDNSCACHE"},
  { SIGHEARTBEAT, "HEARTBEAT"},
  { SIGACTIVE, "ACTIVE" },
  { SIGDORMANT, "DORMANT" },
  { 0, NULL },
};

/** Called when we get a SIGNAL command. React to the provided signal, and
 * report success or failure. (If the signal results in a shutdown, success
 * may not be reported.) */
static int
handle_control_signal(control_connection_t *conn, uint32_t len,
                      const char *body)
{
  int sig = -1;
  int i;
  int n = 0;
  char *s;

  (void) len;

  while (body[n] && ! TOR_ISSPACE(body[n]))
    ++n;
  s = tor_strndup(body, n);

  for (i = 0; signal_table[i].signal_name != NULL; ++i) {
    if (!strcasecmp(s, signal_table[i].signal_name)) {
      sig = signal_table[i].sig;
      break;
    }
  }

  if (sig < 0)
    connection_printf_to_buf(conn, "552 Unrecognized signal code \"%s\"\r\n",
                             s);
  tor_free(s);
  if (sig < 0)
    return 0;

  send_control_done(conn);
  /* Flush the "done" first if the signal might make us shut down. */
  if (sig == SIGTERM || sig == SIGINT)
    connection_flush(TO_CONN(conn));

  activate_signal(sig);

  return 0;
}

/** Called when we get a TAKEOWNERSHIP command.  Mark this connection
 * as an owning connection, so that we will exit if the connection
 * closes. */
static int
handle_control_takeownership(control_connection_t *conn, uint32_t len,
                             const char *body)
{
  (void)len;
  (void)body;

  conn->is_owning_control_connection = 1;

  log_info(LD_CONTROL, "Control connection %d has taken ownership of this "
           "Tor instance.",
           (int)(conn->base_.s));

  send_control_done(conn);
  return 0;
}

/** Called when we get a DROPOWNERSHIP command.  Mark this connection
 * as a non-owning connection, so that we will not exit if the connection
 * closes. */
static int
handle_control_dropownership(control_connection_t *conn, uint32_t len,
                             const char *body)
{
  (void)len;
  (void)body;

  conn->is_owning_control_connection = 0;

  log_info(LD_CONTROL, "Control connection %d has dropped ownership of this "
           "Tor instance.",
           (int)(conn->base_.s));

  send_control_done(conn);
  return 0;
}

/** Return true iff <b>addr</b> is unusable as a mapaddress target because of
 * containing funny characters. */
static int
address_is_invalid_mapaddress_target(const char *addr)
{
  if (!strcmpstart(addr, "*."))
    return address_is_invalid_destination(addr+2, 1);
  else
    return address_is_invalid_destination(addr, 1);
}

/** Called when we get a MAPADDRESS command; try to bind all listed addresses,
 * and report success or failure. */
static int
handle_control_mapaddress(control_connection_t *conn, uint32_t len,
                          const char *body)
{
  smartlist_t *elts;
  smartlist_t *lines;
  smartlist_t *reply;
  char *r;
  size_t sz;
  (void) len; /* body is NUL-terminated, so it's safe to ignore the length. */

  lines = smartlist_new();
  elts = smartlist_new();
  reply = smartlist_new();
  smartlist_split_string(lines, body, " ",
                         SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 0);
  SMARTLIST_FOREACH_BEGIN(lines, char *, line) {
    tor_strlower(line);
    smartlist_split_string(elts, line, "=", 0, 2);
    if (smartlist_len(elts) == 2) {
      const char *from = smartlist_get(elts,0);
      const char *to = smartlist_get(elts,1);
      if (address_is_invalid_mapaddress_target(to)) {
        smartlist_add_asprintf(reply,
                     "512-syntax error: invalid address '%s'", to);
        log_warn(LD_CONTROL,
                 "Skipping invalid argument '%s' in MapAddress msg", to);
      } else if (!strcmp(from, ".") || !strcmp(from, "0.0.0.0") ||
                 !strcmp(from, "::")) {
        const char type =
          !strcmp(from,".") ? RESOLVED_TYPE_HOSTNAME :
          (!strcmp(from, "0.0.0.0") ? RESOLVED_TYPE_IPV4 : RESOLVED_TYPE_IPV6);
        const char *address = addressmap_register_virtual_address(
                                                     type, tor_strdup(to));
        if (!address) {
          smartlist_add_asprintf(reply,
                       "451-resource exhausted: skipping '%s'", line);
          log_warn(LD_CONTROL,
                   "Unable to allocate address for '%s' in MapAddress msg",
                   safe_str_client(line));
        } else {
          smartlist_add_asprintf(reply, "250-%s=%s", address, to);
        }
      } else {
        const char *msg;
        if (addressmap_register_auto(from, to, 1,
                                     ADDRMAPSRC_CONTROLLER, &msg) < 0) {
          smartlist_add_asprintf(reply,
                                 "512-syntax error: invalid address mapping "
                                 " '%s': %s", line, msg);
          log_warn(LD_CONTROL,
                   "Skipping invalid argument '%s' in MapAddress msg: %s",
                   line, msg);
        } else {
          smartlist_add_asprintf(reply, "250-%s", line);
        }
      }
    } else {
      smartlist_add_asprintf(reply, "512-syntax error: mapping '%s' is "
                   "not of expected form 'foo=bar'.", line);
      log_info(LD_CONTROL, "Skipping MapAddress '%s': wrong "
                           "number of items.",
                           safe_str_client(line));
    }
    SMARTLIST_FOREACH(elts, char *, cp, tor_free(cp));
    smartlist_clear(elts);
  } SMARTLIST_FOREACH_END(line);
  SMARTLIST_FOREACH(lines, char *, cp, tor_free(cp));
  smartlist_free(lines);
  smartlist_free(elts);

  if (smartlist_len(reply)) {
    ((char*)smartlist_get(reply,smartlist_len(reply)-1))[3] = ' ';
    r = smartlist_join_strings(reply, "\r\n", 1, &sz);
    connection_buf_add(r, sz, TO_CONN(conn));
    tor_free(r);
  } else {
    const char *response =
      "512 syntax error: not enough arguments to mapaddress.\r\n";
    connection_buf_add(response, strlen(response), TO_CONN(conn));
  }

  SMARTLIST_FOREACH(reply, char *, cp, tor_free(cp));
  smartlist_free(reply);
  return 0;
}

/** Given a string, convert it to a circuit purpose. */
static uint8_t
circuit_purpose_from_string(const char *string)
{
  if (!strcasecmpstart(string, "purpose="))
    string += strlen("purpose=");

  if (!strcasecmp(string, "general"))
    return CIRCUIT_PURPOSE_C_GENERAL;
  else if (!strcasecmp(string, "controller"))
    return CIRCUIT_PURPOSE_CONTROLLER;
  else
    return CIRCUIT_PURPOSE_UNKNOWN;
}

/** Return a newly allocated smartlist containing the arguments to the command
 * waiting in <b>body</b>. If there are fewer than <b>min_args</b> arguments,
 * or if <b>max_args</b> is nonnegative and there are more than
 * <b>max_args</b> arguments, send a 512 error to the controller, using
 * <b>command</b> as the command name in the error message. */
static smartlist_t *
getargs_helper(const char *command, control_connection_t *conn,
               const char *body, int min_args, int max_args)
{
  smartlist_t *args = smartlist_new();
  smartlist_split_string(args, body, " ",
                         SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 0);
  if (smartlist_len(args) < min_args) {
    connection_printf_to_buf(conn, "512 Missing argument to %s\r\n",command);
    goto err;
  } else if (max_args >= 0 && smartlist_len(args) > max_args) {
    connection_printf_to_buf(conn, "512 Too many arguments to %s\r\n",command);
    goto err;
  }
  return args;
 err:
  SMARTLIST_FOREACH(args, char *, s, tor_free(s));
  smartlist_free(args);
  return NULL;
}

/** Helper.  Return the first element of <b>sl</b> at index <b>start_at</b> or
 * higher that starts with <b>prefix</b>, case-insensitive.  Return NULL if no
 * such element exists. */
static const char *
find_element_starting_with(smartlist_t *sl, int start_at, const char *prefix)
{
  int i;
  for (i = start_at; i < smartlist_len(sl); ++i) {
    const char *elt = smartlist_get(sl, i);
    if (!strcasecmpstart(elt, prefix))
      return elt;
  }
  return NULL;
}

/** Helper.  Return true iff s is an argument that we should treat as a
 * key-value pair. */
static int
is_keyval_pair(const char *s)
{
  /* An argument is a key-value pair if it has an =, and it isn't of the form
   * $fingeprint=name */
  return strchr(s, '=') && s[0] != '$';
}

/** Called when we get an EXTENDCIRCUIT message.  Try to extend the listed
 * circuit, and report success or failure. */
static int
handle_control_extendcircuit(control_connection_t *conn, uint32_t len,
                             const char *body)
{
  smartlist_t *router_nicknames=NULL, *nodes=NULL;
  origin_circuit_t *circ = NULL;
  int zero_circ;
  uint8_t intended_purpose = CIRCUIT_PURPOSE_C_GENERAL;
  smartlist_t *args;
  (void) len;

  router_nicknames = smartlist_new();

  args = getargs_helper("EXTENDCIRCUIT", conn, body, 1, -1);
  if (!args)
    goto done;

  zero_circ = !strcmp("0", (char*)smartlist_get(args,0));

  if (zero_circ) {
    const char *purp = find_element_starting_with(args, 1, "PURPOSE=");

    if (purp) {
      intended_purpose = circuit_purpose_from_string(purp);
      if (intended_purpose == CIRCUIT_PURPOSE_UNKNOWN) {
        connection_printf_to_buf(conn, "552 Unknown purpose \"%s\"\r\n", purp);
        SMARTLIST_FOREACH(args, char *, cp, tor_free(cp));
        smartlist_free(args);
        goto done;
      }
    }

    if ((smartlist_len(args) == 1) ||
        (smartlist_len(args) >= 2 && is_keyval_pair(smartlist_get(args, 1)))) {
      // "EXTENDCIRCUIT 0" || EXTENDCIRCUIT 0 foo=bar"
      circ = circuit_launch(intended_purpose, CIRCLAUNCH_NEED_CAPACITY);
      if (!circ) {
        connection_write_str_to_buf("551 Couldn't start circuit\r\n", conn);
      } else {
        connection_printf_to_buf(conn, "250 EXTENDED %lu\r\n",
                  (unsigned long)circ->global_identifier);
      }
      SMARTLIST_FOREACH(args, char *, cp, tor_free(cp));
      smartlist_free(args);
      goto done;
    }
    // "EXTENDCIRCUIT 0 router1,router2" ||
    // "EXTENDCIRCUIT 0 router1,router2 PURPOSE=foo"
  }

  if (!zero_circ && !(circ = get_circ(smartlist_get(args,0)))) {
    connection_printf_to_buf(conn, "552 Unknown circuit \"%s\"\r\n",
                             (char*)smartlist_get(args, 0));
    SMARTLIST_FOREACH(args, char *, cp, tor_free(cp));
    smartlist_free(args);
    goto done;
  }

  if (smartlist_len(args) < 2) {
    connection_printf_to_buf(conn,
                             "512 syntax error: not enough arguments.\r\n");
    SMARTLIST_FOREACH(args, char *, cp, tor_free(cp));
    smartlist_free(args);
    goto done;
  }

  smartlist_split_string(router_nicknames, smartlist_get(args,1), ",", 0, 0);

  SMARTLIST_FOREACH(args, char *, cp, tor_free(cp));
  smartlist_free(args);

  nodes = smartlist_new();
  int first_node = zero_circ;
  SMARTLIST_FOREACH_BEGIN(router_nicknames, const char *, n) {
    const node_t *node = node_get_by_nickname(n, 0);
    if (!node) {
      connection_printf_to_buf(conn, "552 No such router \"%s\"\r\n", n);
      goto done;
    }
    if (!node_has_preferred_descriptor(node, first_node)) {
      connection_printf_to_buf(conn, "552 No descriptor for \"%s\"\r\n", n);
      goto done;
    }
    smartlist_add(nodes, (void*)node);
    first_node = 0;
  } SMARTLIST_FOREACH_END(n);
  if (!smartlist_len(nodes)) {
    connection_write_str_to_buf("512 No router names provided\r\n", conn);
    goto done;
  }

  if (zero_circ) {
    /* start a new circuit */
    circ = origin_circuit_init(intended_purpose, 0);
  }

  /* now circ refers to something that is ready to be extended */
  first_node = zero_circ;
  SMARTLIST_FOREACH(nodes, const node_t *, node,
  {
    extend_info_t *info = extend_info_from_node(node, first_node);
    if (!info) {
      tor_assert_nonfatal(first_node);
      log_warn(LD_CONTROL,
               "controller tried to connect to a node that lacks a suitable "
               "descriptor, or which doesn't have any "
               "addresses that are allowed by the firewall configuration; "
               "circuit marked for closing.");
      circuit_mark_for_close(TO_CIRCUIT(circ), -END_CIRC_REASON_CONNECTFAILED);
      connection_write_str_to_buf("551 Couldn't start circuit\r\n", conn);
      goto done;
    }
    circuit_append_new_exit(circ, info);
    if (circ->build_state->desired_path_len > 1) {
      circ->build_state->onehop_tunnel = 0;
    }
    extend_info_free(info);
    first_node = 0;
  });

  /* now that we've populated the cpath, start extending */
  if (zero_circ) {
    int err_reason = 0;
    if ((err_reason = circuit_handle_first_hop(circ)) < 0) {
      circuit_mark_for_close(TO_CIRCUIT(circ), -err_reason);
      connection_write_str_to_buf("551 Couldn't start circuit\r\n", conn);
      goto done;
    }
  } else {
    if (circ->base_.state == CIRCUIT_STATE_OPEN ||
        circ->base_.state == CIRCUIT_STATE_GUARD_WAIT) {
      int err_reason = 0;
      circuit_set_state(TO_CIRCUIT(circ), CIRCUIT_STATE_BUILDING);
      if ((err_reason = circuit_send_next_onion_skin(circ)) < 0) {
        log_info(LD_CONTROL,
                 "send_next_onion_skin failed; circuit marked for closing.");
        circuit_mark_for_close(TO_CIRCUIT(circ), -err_reason);
        connection_write_str_to_buf("551 Couldn't send onion skin\r\n", conn);
        goto done;
      }
    }
  }

  connection_printf_to_buf(conn, "250 EXTENDED %lu\r\n",
                             (unsigned long)circ->global_identifier);
  if (zero_circ) /* send a 'launched' event, for completeness */
    circuit_event_status(circ, CIRC_EVENT_LAUNCHED, 0);
 done:
  SMARTLIST_FOREACH(router_nicknames, char *, n, tor_free(n));
  smartlist_free(router_nicknames);
  smartlist_free(nodes);
  return 0;
}

/** Called when we get a SETCIRCUITPURPOSE message. If we can find the
 * circuit and it's a valid purpose, change it. */
static int
handle_control_setcircuitpurpose(control_connection_t *conn,
                                 uint32_t len, const char *body)
{
  origin_circuit_t *circ = NULL;
  uint8_t new_purpose;
  smartlist_t *args;
  (void) len; /* body is NUL-terminated, so it's safe to ignore the length. */

  args = getargs_helper("SETCIRCUITPURPOSE", conn, body, 2, -1);
  if (!args)
    goto done;

  if (!(circ = get_circ(smartlist_get(args,0)))) {
    connection_printf_to_buf(conn, "552 Unknown circuit \"%s\"\r\n",
                             (char*)smartlist_get(args, 0));
    goto done;
  }

  {
    const char *purp = find_element_starting_with(args,1,"PURPOSE=");
    if (!purp) {
      connection_write_str_to_buf("552 No purpose given\r\n", conn);
      goto done;
    }
    new_purpose = circuit_purpose_from_string(purp);
    if (new_purpose == CIRCUIT_PURPOSE_UNKNOWN) {
      connection_printf_to_buf(conn, "552 Unknown purpose \"%s\"\r\n", purp);
      goto done;
    }
  }

  circuit_change_purpose(TO_CIRCUIT(circ), new_purpose);
  connection_write_str_to_buf("250 OK\r\n", conn);

 done:
  if (args) {
    SMARTLIST_FOREACH(args, char *, cp, tor_free(cp));
    smartlist_free(args);
  }
  return 0;
}

/** Called when we get an ATTACHSTREAM message.  Try to attach the requested
 * stream, and report success or failure. */
static int
handle_control_attachstream(control_connection_t *conn, uint32_t len,
                            const char *body)
{
  entry_connection_t *ap_conn = NULL;
  origin_circuit_t *circ = NULL;
  int zero_circ;
  smartlist_t *args;
  crypt_path_t *cpath=NULL;
  int hop=0, hop_line_ok=1;
  (void) len;

  args = getargs_helper("ATTACHSTREAM", conn, body, 2, -1);
  if (!args)
    return 0;

  zero_circ = !strcmp("0", (char*)smartlist_get(args,1));

  if (!(ap_conn = get_stream(smartlist_get(args, 0)))) {
    connection_printf_to_buf(conn, "552 Unknown stream \"%s\"\r\n",
                             (char*)smartlist_get(args, 0));
  } else if (!zero_circ && !(circ = get_circ(smartlist_get(args, 1)))) {
    connection_printf_to_buf(conn, "552 Unknown circuit \"%s\"\r\n",
                             (char*)smartlist_get(args, 1));
  } else if (circ) {
    const char *hopstring = find_element_starting_with(args,2,"HOP=");
    if (hopstring) {
      hopstring += strlen("HOP=");
      hop = (int) tor_parse_ulong(hopstring, 10, 0, INT_MAX,
                                  &hop_line_ok, NULL);
      if (!hop_line_ok) { /* broken hop line */
        connection_printf_to_buf(conn, "552 Bad value hop=%s\r\n", hopstring);
      }
    }
  }
  SMARTLIST_FOREACH(args, char *, cp, tor_free(cp));
  smartlist_free(args);
  if (!ap_conn || (!zero_circ && !circ) || !hop_line_ok)
    return 0;

  if (ENTRY_TO_CONN(ap_conn)->state != AP_CONN_STATE_CONTROLLER_WAIT &&
      ENTRY_TO_CONN(ap_conn)->state != AP_CONN_STATE_CONNECT_WAIT &&
      ENTRY_TO_CONN(ap_conn)->state != AP_CONN_STATE_RESOLVE_WAIT) {
    connection_write_str_to_buf(
                    "555 Connection is not managed by controller.\r\n",
                    conn);
    return 0;
  }

  /* Do we need to detach it first? */
  if (ENTRY_TO_CONN(ap_conn)->state != AP_CONN_STATE_CONTROLLER_WAIT) {
    edge_connection_t *edge_conn = ENTRY_TO_EDGE_CONN(ap_conn);
    circuit_t *tmpcirc = circuit_get_by_edge_conn(edge_conn);
    connection_edge_end(edge_conn, END_STREAM_REASON_TIMEOUT);
    /* Un-mark it as ending, since we're going to reuse it. */
    edge_conn->edge_has_sent_end = 0;
    edge_conn->end_reason = 0;
    if (tmpcirc)
      circuit_detach_stream(tmpcirc, edge_conn);
    CONNECTION_AP_EXPECT_NONPENDING(ap_conn);
    TO_CONN(edge_conn)->state = AP_CONN_STATE_CONTROLLER_WAIT;
  }

  if (circ && (circ->base_.state != CIRCUIT_STATE_OPEN)) {
    connection_write_str_to_buf(
                    "551 Can't attach stream to non-open origin circuit\r\n",
                    conn);
    return 0;
  }
  /* Is this a single hop circuit? */
  if (circ && (circuit_get_cpath_len(circ)<2 || hop==1)) {
    connection_write_str_to_buf(
               "551 Can't attach stream to this one-hop circuit.\r\n", conn);
    return 0;
  }

  if (circ && hop>0) {
    /* find this hop in the circuit, and set cpath */
    cpath = circuit_get_cpath_hop(circ, hop);
    if (!cpath) {
      connection_printf_to_buf(conn,
                               "551 Circuit doesn't have %d hops.\r\n", hop);
      return 0;
    }
  }
  if (connection_ap_handshake_rewrite_and_attach(ap_conn, circ, cpath) < 0) {
    connection_write_str_to_buf("551 Unable to attach stream\r\n", conn);
    return 0;
  }
  send_control_done(conn);
  return 0;
}

/** Called when we get a POSTDESCRIPTOR message.  Try to learn the provided
 * descriptor, and report success or failure. */
static int
handle_control_postdescriptor(control_connection_t *conn, uint32_t len,
                              const char *body)
{
  char *desc;
  const char *msg=NULL;
  uint8_t purpose = ROUTER_PURPOSE_GENERAL;
  int cache = 0; /* eventually, we may switch this to 1 */

  const char *cp = memchr(body, '\n', len);

  if (cp == NULL) {
    connection_printf_to_buf(conn, "251 Empty body\r\n");
    return 0;
  }
  ++cp;

  char *cmdline = tor_memdup_nulterm(body, cp-body);
  smartlist_t *args = smartlist_new();
  smartlist_split_string(args, cmdline, " ",
                         SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 0);
  SMARTLIST_FOREACH_BEGIN(args, char *, option) {
    if (!strcasecmpstart(option, "purpose=")) {
      option += strlen("purpose=");
      purpose = router_purpose_from_string(option);
      if (purpose == ROUTER_PURPOSE_UNKNOWN) {
        connection_printf_to_buf(conn, "552 Unknown purpose \"%s\"\r\n",
                                 option);
        goto done;
      }
    } else if (!strcasecmpstart(option, "cache=")) {
      option += strlen("cache=");
      if (!strcasecmp(option, "no"))
        cache = 0;
      else if (!strcasecmp(option, "yes"))
        cache = 1;
      else {
        connection_printf_to_buf(conn, "552 Unknown cache request \"%s\"\r\n",
                                 option);
        goto done;
      }
    } else { /* unrecognized argument? */
      connection_printf_to_buf(conn,
        "512 Unexpected argument \"%s\" to postdescriptor\r\n", option);
      goto done;
    }
  } SMARTLIST_FOREACH_END(option);

  read_escaped_data(cp, len-(cp-body), &desc);

  switch (router_load_single_router(desc, purpose, cache, &msg)) {
  case -1:
    if (!msg) msg = "Could not parse descriptor";
    connection_printf_to_buf(conn, "554 %s\r\n", msg);
    break;
  case 0:
    if (!msg) msg = "Descriptor not added";
    connection_printf_to_buf(conn, "251 %s\r\n",msg);
    break;
  case 1:
    send_control_done(conn);
    break;
  }

  tor_free(desc);
 done:
  SMARTLIST_FOREACH(args, char *, arg, tor_free(arg));
  smartlist_free(args);
  tor_free(cmdline);
  return 0;
}

/** Called when we receive a REDIRECTSTERAM command.  Try to change the target
 * address of the named AP stream, and report success or failure. */
static int
handle_control_redirectstream(control_connection_t *conn, uint32_t len,
                              const char *body)
{
  entry_connection_t *ap_conn = NULL;
  char *new_addr = NULL;
  uint16_t new_port = 0;
  smartlist_t *args;
  (void) len;

  args = getargs_helper("REDIRECTSTREAM", conn, body, 2, -1);
  if (!args)
    return 0;

  if (!(ap_conn = get_stream(smartlist_get(args, 0)))
           || !ap_conn->socks_request) {
    connection_printf_to_buf(conn, "552 Unknown stream \"%s\"\r\n",
                             (char*)smartlist_get(args, 0));
  } else {
    int ok = 1;
    if (smartlist_len(args) > 2) { /* they included a port too */
      new_port = (uint16_t) tor_parse_ulong(smartlist_get(args, 2),
                                            10, 1, 65535, &ok, NULL);
    }
    if (!ok) {
      connection_printf_to_buf(conn, "512 Cannot parse port \"%s\"\r\n",
                               (char*)smartlist_get(args, 2));
    } else {
      new_addr = tor_strdup(smartlist_get(args, 1));
    }
  }

  SMARTLIST_FOREACH(args, char *, cp, tor_free(cp));
  smartlist_free(args);
  if (!new_addr)
    return 0;

  strlcpy(ap_conn->socks_request->address, new_addr,
          sizeof(ap_conn->socks_request->address));
  if (new_port)
    ap_conn->socks_request->port = new_port;
  tor_free(new_addr);
  send_control_done(conn);
  return 0;
}

/** Called when we get a CLOSESTREAM command; try to close the named stream
 * and report success or failure. */
static int
handle_control_closestream(control_connection_t *conn, uint32_t len,
                           const char *body)
{
  entry_connection_t *ap_conn=NULL;
  uint8_t reason=0;
  smartlist_t *args;
  int ok;
  (void) len;

  args = getargs_helper("CLOSESTREAM", conn, body, 2, -1);
  if (!args)
    return 0;

  else if (!(ap_conn = get_stream(smartlist_get(args, 0))))
    connection_printf_to_buf(conn, "552 Unknown stream \"%s\"\r\n",
                             (char*)smartlist_get(args, 0));
  else {
    reason = (uint8_t) tor_parse_ulong(smartlist_get(args,1), 10, 0, 255,
                                       &ok, NULL);
    if (!ok) {
      connection_printf_to_buf(conn, "552 Unrecognized reason \"%s\"\r\n",
                               (char*)smartlist_get(args, 1));
      ap_conn = NULL;
    }
  }
  SMARTLIST_FOREACH(args, char *, cp, tor_free(cp));
  smartlist_free(args);
  if (!ap_conn)
    return 0;

  connection_mark_unattached_ap(ap_conn, reason);
  send_control_done(conn);
  return 0;
}

/** Called when we get a CLOSECIRCUIT command; try to close the named circuit
 * and report success or failure. */
static int
handle_control_closecircuit(control_connection_t *conn, uint32_t len,
                            const char *body)
{
  origin_circuit_t *circ = NULL;
  int safe = 0;
  smartlist_t *args;
  (void) len;

  args = getargs_helper("CLOSECIRCUIT", conn, body, 1, -1);
  if (!args)
    return 0;

  if (!(circ=get_circ(smartlist_get(args, 0))))
    connection_printf_to_buf(conn, "552 Unknown circuit \"%s\"\r\n",
                             (char*)smartlist_get(args, 0));
  else {
    int i;
    for (i=1; i < smartlist_len(args); ++i) {
      if (!strcasecmp(smartlist_get(args, i), "IfUnused"))
        safe = 1;
      else
        log_info(LD_CONTROL, "Skipping unknown option %s",
                 (char*)smartlist_get(args,i));
    }
  }
  SMARTLIST_FOREACH(args, char *, cp, tor_free(cp));
  smartlist_free(args);
  if (!circ)
    return 0;

  if (!safe || !circ->p_streams) {
    circuit_mark_for_close(TO_CIRCUIT(circ), END_CIRC_REASON_REQUESTED);
  }

  send_control_done(conn);
  return 0;
}

/** Called when we get a RESOLVE command: start trying to resolve
 * the listed addresses. */
static int
handle_control_resolve(control_connection_t *conn, uint32_t len,
                       const char *body)
{
  smartlist_t *args, *failed;
  int is_reverse = 0;
  (void) len; /* body is nul-terminated; it's safe to ignore the length */

  if (!(conn->event_mask & (((event_mask_t)1)<<EVENT_ADDRMAP))) {
    log_warn(LD_CONTROL, "Controller asked us to resolve an address, but "
             "isn't listening for ADDRMAP events.  It probably won't see "
             "the answer.");
  }
  args = smartlist_new();
  smartlist_split_string(args, body, " ",
                         SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 0);
  {
    const char *modearg = find_element_starting_with(args, 0, "mode=");
    if (modearg && !strcasecmp(modearg, "mode=reverse"))
      is_reverse = 1;
  }
  failed = smartlist_new();
  SMARTLIST_FOREACH(args, const char *, arg, {
      if (!is_keyval_pair(arg)) {
          if (dnsserv_launch_request(arg, is_reverse, conn)<0)
            smartlist_add(failed, (char*)arg);
      }
  });

  send_control_done(conn);
  SMARTLIST_FOREACH(failed, const char *, arg, {
      control_event_address_mapped(arg, arg, time(NULL),
                                   "internal", 0);
  });

  SMARTLIST_FOREACH(args, char *, cp, tor_free(cp));
  smartlist_free(args);
  smartlist_free(failed);
  return 0;
}

/** Called when we get a PROTOCOLINFO command: send back a reply. */
static int
handle_control_protocolinfo(control_connection_t *conn, uint32_t len,
                            const char *body)
{
  const char *bad_arg = NULL;
  smartlist_t *args;
  (void)len;

  conn->have_sent_protocolinfo = 1;
  args = smartlist_new();
  smartlist_split_string(args, body, " ",
                         SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 0);
  SMARTLIST_FOREACH(args, const char *, arg, {
      int ok;
      tor_parse_long(arg, 10, 0, LONG_MAX, &ok, NULL);
      if (!ok) {
        bad_arg = arg;
        break;
      }
    });
  if (bad_arg) {
    connection_printf_to_buf(conn, "513 No such version %s\r\n",
                             escaped(bad_arg));
    /* Don't tolerate bad arguments when not authenticated. */
    if (!STATE_IS_OPEN(TO_CONN(conn)->state))
      connection_mark_for_close(TO_CONN(conn));
    goto done;
  } else {
    const or_options_t *options = get_options();
    int cookies = options->CookieAuthentication;
    char *cfile = get_controller_cookie_file_name();
    char *abs_cfile;
    char *esc_cfile;
    char *methods;
    abs_cfile = make_path_absolute(cfile);
    esc_cfile = esc_for_log(abs_cfile);
    {
      int passwd = (options->HashedControlPassword != NULL ||
                    options->HashedControlSessionPassword != NULL);
      smartlist_t *mlist = smartlist_new();
      if (cookies) {
        smartlist_add(mlist, (char*)"COOKIE");
        smartlist_add(mlist, (char*)"SAFECOOKIE");
      }
      if (passwd)
        smartlist_add(mlist, (char*)"HASHEDPASSWORD");
      if (!cookies && !passwd)
        smartlist_add(mlist, (char*)"NULL");
      methods = smartlist_join_strings(mlist, ",", 0, NULL);
      smartlist_free(mlist);
    }

    connection_printf_to_buf(conn,
                             "250-PROTOCOLINFO 1\r\n"
                             "250-AUTH METHODS=%s%s%s\r\n"
                             "250-VERSION Tor=%s\r\n"
                             "250 OK\r\n",
                             methods,
                             cookies?" COOKIEFILE=":"",
                             cookies?esc_cfile:"",
                             escaped(VERSION));
    tor_free(methods);
    tor_free(cfile);
    tor_free(abs_cfile);
    tor_free(esc_cfile);
  }
 done:
  SMARTLIST_FOREACH(args, char *, cp, tor_free(cp));
  smartlist_free(args);
  return 0;
}

/** Called when we get an AUTHCHALLENGE command. */
static int
handle_control_authchallenge(control_connection_t *conn, uint32_t len,
                             const char *body)
{
  const char *cp = body;
  char *client_nonce;
  size_t client_nonce_len;
  char server_hash[DIGEST256_LEN];
  char server_hash_encoded[HEX_DIGEST256_LEN+1];
  char server_nonce[SAFECOOKIE_SERVER_NONCE_LEN];
  char server_nonce_encoded[(2*SAFECOOKIE_SERVER_NONCE_LEN) + 1];

  cp += strspn(cp, " \t\n\r");
  if (!strcasecmpstart(cp, "SAFECOOKIE")) {
    cp += strlen("SAFECOOKIE");
  } else {
    connection_write_str_to_buf("513 AUTHCHALLENGE only supports SAFECOOKIE "
                                "authentication\r\n", conn);
    connection_mark_for_close(TO_CONN(conn));
    return -1;
  }

  if (!authentication_cookie_is_set) {
    connection_write_str_to_buf("515 Cookie authentication is disabled\r\n",
                                conn);
    connection_mark_for_close(TO_CONN(conn));
    return -1;
  }

  cp += strspn(cp, " \t\n\r");
  if (*cp == '"') {
    const char *newcp =
      decode_escaped_string(cp, len - (cp - body),
                            &client_nonce, &client_nonce_len);
    if (newcp == NULL) {
      connection_write_str_to_buf("513 Invalid quoted client nonce\r\n",
                                  conn);
      connection_mark_for_close(TO_CONN(conn));
      return -1;
    }
    cp = newcp;
  } else {
    size_t client_nonce_encoded_len = strspn(cp, "0123456789ABCDEFabcdef");

    client_nonce_len = client_nonce_encoded_len / 2;
    client_nonce = tor_malloc_zero(client_nonce_len);

    if (base16_decode(client_nonce, client_nonce_len,
                      cp, client_nonce_encoded_len)
                      != (int) client_nonce_len) {
      connection_write_str_to_buf("513 Invalid base16 client nonce\r\n",
                                  conn);
      connection_mark_for_close(TO_CONN(conn));
      tor_free(client_nonce);
      return -1;
    }

    cp += client_nonce_encoded_len;
  }

  cp += strspn(cp, " \t\n\r");
  if (*cp != '\0' ||
      cp != body + len) {
    connection_write_str_to_buf("513 Junk at end of AUTHCHALLENGE command\r\n",
                                conn);
    connection_mark_for_close(TO_CONN(conn));
    tor_free(client_nonce);
    return -1;
  }
  crypto_rand(server_nonce, SAFECOOKIE_SERVER_NONCE_LEN);

  /* Now compute and send the server-to-controller response, and the
   * server's nonce. */
  tor_assert(authentication_cookie != NULL);

  {
    size_t tmp_len = (AUTHENTICATION_COOKIE_LEN +
                      client_nonce_len +
                      SAFECOOKIE_SERVER_NONCE_LEN);
    char *tmp = tor_malloc_zero(tmp_len);
    char *client_hash = tor_malloc_zero(DIGEST256_LEN);
    memcpy(tmp, authentication_cookie, AUTHENTICATION_COOKIE_LEN);
    memcpy(tmp + AUTHENTICATION_COOKIE_LEN, client_nonce, client_nonce_len);
    memcpy(tmp + AUTHENTICATION_COOKIE_LEN + client_nonce_len,
           server_nonce, SAFECOOKIE_SERVER_NONCE_LEN);

    crypto_hmac_sha256(server_hash,
                       SAFECOOKIE_SERVER_TO_CONTROLLER_CONSTANT,
                       strlen(SAFECOOKIE_SERVER_TO_CONTROLLER_CONSTANT),
                       tmp,
                       tmp_len);

    crypto_hmac_sha256(client_hash,
                       SAFECOOKIE_CONTROLLER_TO_SERVER_CONSTANT,
                       strlen(SAFECOOKIE_CONTROLLER_TO_SERVER_CONSTANT),
                       tmp,
                       tmp_len);

    conn->safecookie_client_hash = client_hash;

    tor_free(tmp);
  }

  base16_encode(server_hash_encoded, sizeof(server_hash_encoded),
                server_hash, sizeof(server_hash));
  base16_encode(server_nonce_encoded, sizeof(server_nonce_encoded),
                server_nonce, sizeof(server_nonce));

  connection_printf_to_buf(conn,
                           "250 AUTHCHALLENGE SERVERHASH=%s "
                           "SERVERNONCE=%s\r\n",
                           server_hash_encoded,
                           server_nonce_encoded);

  tor_free(client_nonce);
  return 0;
}

/** Called when we get a USEFEATURE command: parse the feature list, and
 * set up the control_connection's options properly. */
static int
handle_control_usefeature(control_connection_t *conn,
                          uint32_t len,
                          const char *body)
{
  smartlist_t *args;
  int bad = 0;
  (void) len; /* body is nul-terminated; it's safe to ignore the length */
  args = smartlist_new();
  smartlist_split_string(args, body, " ",
                         SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 0);
  SMARTLIST_FOREACH_BEGIN(args, const char *, arg) {
      if (!strcasecmp(arg, "VERBOSE_NAMES"))
        ;
      else if (!strcasecmp(arg, "EXTENDED_EVENTS"))
        ;
      else {
        connection_printf_to_buf(conn, "552 Unrecognized feature \"%s\"\r\n",
                                 arg);
        bad = 1;
        break;
      }
  } SMARTLIST_FOREACH_END(arg);

  if (!bad) {
    send_control_done(conn);
  }

  SMARTLIST_FOREACH(args, char *, cp, tor_free(cp));
  smartlist_free(args);
  return 0;
}

/** Implementation for the DROPGUARDS command. */
static int
handle_control_dropguards(control_connection_t *conn,
                          uint32_t len,
                          const char *body)
{
  smartlist_t *args;
  (void) len; /* body is nul-terminated; it's safe to ignore the length */
  args = smartlist_new();
  smartlist_split_string(args, body, " ",
                         SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 0);

  static int have_warned = 0;
  if (! have_warned) {
    log_warn(LD_CONTROL, "DROPGUARDS is dangerous; make sure you understand "
             "the risks before using it. It may be removed in a future "
             "version of Tor.");
    have_warned = 1;
  }

  if (smartlist_len(args)) {
    connection_printf_to_buf(conn, "512 Too many arguments to DROPGUARDS\r\n");
  } else {
    remove_all_entry_guards();
    send_control_done(conn);
  }

  SMARTLIST_FOREACH(args, char *, cp, tor_free(cp));
  smartlist_free(args);
  return 0;
}

/** Implementation for the HSFETCH command. */
static int
handle_control_hsfetch(control_connection_t *conn, uint32_t len,
                       const char *body)
{
  int i;
  char digest[DIGEST_LEN], *hsaddress = NULL, *arg1 = NULL, *desc_id = NULL;
  smartlist_t *args = NULL, *hsdirs = NULL;
  (void) len; /* body is nul-terminated; it's safe to ignore the length */
  static const char *hsfetch_command = "HSFETCH";
  static const char *v2_str = "v2-";
  const size_t v2_str_len = strlen(v2_str);
  rend_data_t *rend_query = NULL;
  ed25519_public_key_t v3_pk;
  uint32_t version;

  /* Make sure we have at least one argument, the HSAddress. */
  args = getargs_helper(hsfetch_command, conn, body, 1, -1);
  if (!args) {
    goto exit;
  }

  /* Extract the first argument (either HSAddress or DescID). */
  arg1 = smartlist_get(args, 0);
  /* Test if it's an HS address without the .onion part. */
  if (rend_valid_v2_service_id(arg1)) {
    hsaddress = arg1;
    version = HS_VERSION_TWO;
  } else if (strcmpstart(arg1, v2_str) == 0 &&
             rend_valid_descriptor_id(arg1 + v2_str_len) &&
             base32_decode(digest, sizeof(digest), arg1 + v2_str_len,
                           REND_DESC_ID_V2_LEN_BASE32) ==
                REND_DESC_ID_V2_LEN_BASE32) {
    /* We have a well formed version 2 descriptor ID. Keep the decoded value
     * of the id. */
    desc_id = digest;
    version = HS_VERSION_TWO;
  } else if (hs_address_is_valid(arg1)) {
    hsaddress = arg1;
    version = HS_VERSION_THREE;
    hs_parse_address(hsaddress, &v3_pk, NULL, NULL);
  } else {
    connection_printf_to_buf(conn, "513 Invalid argument \"%s\"\r\n",
                             arg1);
    goto done;
  }

  static const char *opt_server = "SERVER=";

  /* Skip first argument because it's the HSAddress or DescID. */
  for (i = 1; i < smartlist_len(args); ++i) {
    const char *arg = smartlist_get(args, i);
    const node_t *node;

    if (!strcasecmpstart(arg, opt_server)) {
      const char *server;

      server = arg + strlen(opt_server);
      node = node_get_by_hex_id(server, 0);
      if (!node) {
        connection_printf_to_buf(conn, "552 Server \"%s\" not found\r\n",
                                 server);
        goto done;
      }
      if (!hsdirs) {
        /* Stores routerstatus_t object for each specified server. */
        hsdirs = smartlist_new();
      }
      /* Valid server, add it to our local list. */
      smartlist_add(hsdirs, node->rs);
    } else {
      connection_printf_to_buf(conn, "513 Unexpected argument \"%s\"\r\n",
                               arg);
      goto done;
    }
  }

  if (version == HS_VERSION_TWO) {
    rend_query = rend_data_client_create(hsaddress, desc_id, NULL,
                                         REND_NO_AUTH);
    if (rend_query == NULL) {
      connection_printf_to_buf(conn, "551 Error creating the HS query\r\n");
      goto done;
    }
  }

  /* Using a descriptor ID, we force the user to provide at least one
   * hsdir server using the SERVER= option. */
  if (desc_id && (!hsdirs || !smartlist_len(hsdirs))) {
      connection_printf_to_buf(conn, "512 %s option is required\r\n",
                               opt_server);
      goto done;
  }

  /* We are about to trigger HSDir fetch so send the OK now because after
   * that 650 event(s) are possible so better to have the 250 OK before them
   * to avoid out of order replies. */
  send_control_done(conn);

  /* Trigger the fetch using the built rend query and possibly a list of HS
   * directory to use. This function ignores the client cache thus this will
   * always send a fetch command. */
  if (version == HS_VERSION_TWO) {
    rend_client_fetch_v2_desc(rend_query, hsdirs);
  } else if (version == HS_VERSION_THREE) {
    hs_control_hsfetch_command(&v3_pk, hsdirs);
  }

 done:
  SMARTLIST_FOREACH(args, char *, cp, tor_free(cp));
  smartlist_free(args);
  /* Contains data pointer that we don't own thus no cleanup. */
  smartlist_free(hsdirs);
  rend_data_free(rend_query);
 exit:
  return 0;
}

/** Implementation for the HSPOST command. */
static int
handle_control_hspost(control_connection_t *conn,
                      uint32_t len,
                      const char *body)
{
  static const char *opt_server = "SERVER=";
  static const char *opt_hsaddress = "HSADDRESS=";
  smartlist_t *hs_dirs = NULL;
  const char *encoded_desc = body;
  size_t encoded_desc_len = len;
  const char *onion_address = NULL;

  char *cp = memchr(body, '\n', len);
  if (cp == NULL) {
    connection_printf_to_buf(conn, "251 Empty body\r\n");
    return 0;
  }
  char *argline = tor_strndup(body, cp-body);

  smartlist_t *args = smartlist_new();

  /* If any SERVER= or HSADDRESS= options were specified, try to parse
   * the options line. */
  if (!strcasecmpstart(argline, opt_server) ||
      !strcasecmpstart(argline, opt_hsaddress)) {
    /* encoded_desc begins after a newline character */
    cp = cp + 1;
    encoded_desc = cp;
    encoded_desc_len = len-(cp-body);

    smartlist_split_string(args, argline, " ",
                           SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 0);
    SMARTLIST_FOREACH_BEGIN(args, const char *, arg) {
      if (!strcasecmpstart(arg, opt_server)) {
        const char *server = arg + strlen(opt_server);
        const node_t *node = node_get_by_hex_id(server, 0);

        if (!node || !node->rs) {
          connection_printf_to_buf(conn, "552 Server \"%s\" not found\r\n",
                                   server);
          goto done;
        }
        /* Valid server, add it to our local list. */
        if (!hs_dirs)
          hs_dirs = smartlist_new();
        smartlist_add(hs_dirs, node->rs);
      } else if (!strcasecmpstart(arg, opt_hsaddress)) {
        const char *address = arg + strlen(opt_hsaddress);
        if (!hs_address_is_valid(address)) {
          connection_printf_to_buf(conn, "512 Malformed onion address\r\n");
          goto done;
        }
        onion_address = address;
      } else {
        connection_printf_to_buf(conn, "512 Unexpected argument \"%s\"\r\n",
                                 arg);
        goto done;
      }
    } SMARTLIST_FOREACH_END(arg);
  }

  /* Handle the v3 case. */
  if (onion_address) {
    char *desc_str = NULL;
    read_escaped_data(encoded_desc, encoded_desc_len, &desc_str);
    if (hs_control_hspost_command(desc_str, onion_address, hs_dirs) < 0) {
      connection_printf_to_buf(conn, "554 Invalid descriptor\r\n");
    } else {
      send_control_done(conn);
    }
    tor_free(desc_str);
    goto done;
  }

  /* From this point on, it is only v2. */

  /* Read the dot encoded descriptor, and parse it. */
  rend_encoded_v2_service_descriptor_t *desc =
      tor_malloc_zero(sizeof(rend_encoded_v2_service_descriptor_t));
  read_escaped_data(encoded_desc, encoded_desc_len, &desc->desc_str);

  rend_service_descriptor_t *parsed = NULL;
  char *intro_content = NULL;
  size_t intro_size;
  size_t encoded_size;
  const char *next_desc;
  if (!rend_parse_v2_service_descriptor(&parsed, desc->desc_id, &intro_content,
                                        &intro_size, &encoded_size,
                                        &next_desc, desc->desc_str, 1)) {
    /* Post the descriptor. */
    char serviceid[REND_SERVICE_ID_LEN_BASE32+1];
    if (!rend_get_service_id(parsed->pk, serviceid)) {
      smartlist_t *descs = smartlist_new();
      smartlist_add(descs, desc);

      /* We are about to trigger HS descriptor upload so send the OK now
       * because after that 650 event(s) are possible so better to have the
       * 250 OK before them to avoid out of order replies. */
      send_control_done(conn);

      /* Trigger the descriptor upload */
      directory_post_to_hs_dir(parsed, descs, hs_dirs, serviceid, 0);
      smartlist_free(descs);
    }

    rend_service_descriptor_free(parsed);
  } else {
    connection_printf_to_buf(conn, "554 Invalid descriptor\r\n");
  }

  tor_free(intro_content);
  rend_encoded_v2_service_descriptor_free(desc);
 done:
  tor_free(argline);
  smartlist_free(hs_dirs); /* Contents belong to the rend service code. */
  SMARTLIST_FOREACH(args, char *, arg, tor_free(arg));
  smartlist_free(args);
  return 0;
}

/* Helper function for ADD_ONION that adds an ephemeral service depending on
 * the given hs_version.
 *
 * The secret key in pk depends on the hs_version. The ownership of the key
 * used in pk is given to the HS subsystem so the caller must stop accessing
 * it after.
 *
 * The port_cfgs is a list of service port. Ownership transferred to service.
 * The max_streams refers to the MaxStreams= key.
 * The max_streams_close_circuit refers to the MaxStreamsCloseCircuit key.
 * The auth_type is the authentication type of the clients in auth_clients.
 * The ownership of that list is transferred to the service.
 *
 * On success (RSAE_OKAY), the address_out points to a newly allocated string
 * containing the onion address without the .onion part. On error, address_out
 * is untouched. */
static hs_service_add_ephemeral_status_t
add_onion_helper_add_service(int hs_version,
                             add_onion_secret_key_t *pk,
                             smartlist_t *port_cfgs, int max_streams,
                             int max_streams_close_circuit, int auth_type,
                             smartlist_t *auth_clients, char **address_out)
{
  hs_service_add_ephemeral_status_t ret;

  tor_assert(pk);
  tor_assert(port_cfgs);
  tor_assert(address_out);

  switch (hs_version) {
  case HS_VERSION_TWO:
    ret = rend_service_add_ephemeral(pk->v2, port_cfgs, max_streams,
                                     max_streams_close_circuit, auth_type,
                                     auth_clients, address_out);
    break;
  case HS_VERSION_THREE:
    ret = hs_service_add_ephemeral(pk->v3, port_cfgs, max_streams,
                                   max_streams_close_circuit, address_out);
    break;
  default:
    tor_assert_unreached();
  }

  return ret;
}

/**
 *
 **/
smartlist_t *
get_detached_onion_services(void)
{
  return detached_onion_services;
}

/** Called when we get a ADD_ONION command; parse the body, and set up
 * the new ephemeral Onion Service. */
static int
handle_control_add_onion(control_connection_t *conn,
                         uint32_t len,
                         const char *body)
{
  smartlist_t *args;
  int arg_len;
  (void) len; /* body is nul-terminated; it's safe to ignore the length */
  args = getargs_helper("ADD_ONION", conn, body, 2, -1);
  if (!args)
    return 0;
  arg_len = smartlist_len(args);

  /* Parse all of the arguments that do not involve handling cryptographic
   * material first, since there's no reason to touch that at all if any of
   * the other arguments are malformed.
   */
  smartlist_t *port_cfgs = smartlist_new();
  smartlist_t *auth_clients = NULL;
  smartlist_t *auth_created_clients = NULL;
  int discard_pk = 0;
  int detach = 0;
  int max_streams = 0;
  int max_streams_close_circuit = 0;
  rend_auth_type_t auth_type = REND_NO_AUTH;
  /* Default to adding an anonymous hidden service if no flag is given */
  int non_anonymous = 0;
  for (int i = 1; i < arg_len; i++) {
    static const char *port_prefix = "Port=";
    static const char *flags_prefix = "Flags=";
    static const char *max_s_prefix = "MaxStreams=";
    static const char *auth_prefix = "ClientAuth=";

    const char *arg = smartlist_get(args, (int)i);
    if (!strcasecmpstart(arg, port_prefix)) {
      /* "Port=VIRTPORT[,TARGET]". */
      const char *port_str = arg + strlen(port_prefix);

      rend_service_port_config_t *cfg =
          rend_service_parse_port_config(port_str, ",", NULL);
      if (!cfg) {
        connection_printf_to_buf(conn, "512 Invalid VIRTPORT/TARGET\r\n");
        goto out;
      }
      smartlist_add(port_cfgs, cfg);
    } else if (!strcasecmpstart(arg, max_s_prefix)) {
      /* "MaxStreams=[0..65535]". */
      const char *max_s_str = arg + strlen(max_s_prefix);
      int ok = 0;
      max_streams = (int)tor_parse_long(max_s_str, 10, 0, 65535, &ok, NULL);
      if (!ok) {
        connection_printf_to_buf(conn, "512 Invalid MaxStreams\r\n");
        goto out;
      }
    } else if (!strcasecmpstart(arg, flags_prefix)) {
      /* "Flags=Flag[,Flag]", where Flag can be:
       *   * 'DiscardPK' - If tor generates the keypair, do not include it in
       *                   the response.
       *   * 'Detach' - Do not tie this onion service to any particular control
       *                connection.
       *   * 'MaxStreamsCloseCircuit' - Close the circuit if MaxStreams is
       *                                exceeded.
       *   * 'BasicAuth' - Client authorization using the 'basic' method.
       *   * 'NonAnonymous' - Add a non-anonymous Single Onion Service. If this
       *                      flag is present, tor must be in non-anonymous
       *                      hidden service mode. If this flag is absent,
       *                      tor must be in anonymous hidden service mode.
       */
      static const char *discard_flag = "DiscardPK";
      static const char *detach_flag = "Detach";
      static const char *max_s_close_flag = "MaxStreamsCloseCircuit";
      static const char *basicauth_flag = "BasicAuth";
      static const char *non_anonymous_flag = "NonAnonymous";

      smartlist_t *flags = smartlist_new();
      int bad = 0;

      smartlist_split_string(flags, arg + strlen(flags_prefix), ",",
                             SPLIT_IGNORE_BLANK, 0);
      if (smartlist_len(flags) < 1) {
        connection_printf_to_buf(conn, "512 Invalid 'Flags' argument\r\n");
        bad = 1;
      }
      SMARTLIST_FOREACH_BEGIN(flags, const char *, flag)
      {
        if (!strcasecmp(flag, discard_flag)) {
          discard_pk = 1;
        } else if (!strcasecmp(flag, detach_flag)) {
          detach = 1;
        } else if (!strcasecmp(flag, max_s_close_flag)) {
          max_streams_close_circuit = 1;
        } else if (!strcasecmp(flag, basicauth_flag)) {
          auth_type = REND_BASIC_AUTH;
        } else if (!strcasecmp(flag, non_anonymous_flag)) {
          non_anonymous = 1;
        } else {
          connection_printf_to_buf(conn,
                                   "512 Invalid 'Flags' argument: %s\r\n",
                                   escaped(flag));
          bad = 1;
          break;
        }
      } SMARTLIST_FOREACH_END(flag);
      SMARTLIST_FOREACH(flags, char *, cp, tor_free(cp));
      smartlist_free(flags);
      if (bad)
        goto out;
    } else if (!strcasecmpstart(arg, auth_prefix)) {
      char *err_msg = NULL;
      int created = 0;
      rend_authorized_client_t *client =
        add_onion_helper_clientauth(arg + strlen(auth_prefix),
                                    &created, &err_msg);
      if (!client) {
        if (err_msg) {
          connection_write_str_to_buf(err_msg, conn);
          tor_free(err_msg);
        }
        goto out;
      }

      if (auth_clients != NULL) {
        int bad = 0;
        SMARTLIST_FOREACH_BEGIN(auth_clients, rend_authorized_client_t *, ac) {
          if (strcmp(ac->client_name, client->client_name) == 0) {
            bad = 1;
            break;
          }
        } SMARTLIST_FOREACH_END(ac);
        if (bad) {
          connection_printf_to_buf(conn,
                                   "512 Duplicate name in ClientAuth\r\n");
          rend_authorized_client_free(client);
          goto out;
        }
      } else {
        auth_clients = smartlist_new();
        auth_created_clients = smartlist_new();
      }
      smartlist_add(auth_clients, client);
      if (created) {
        smartlist_add(auth_created_clients, client);
      }
    } else {
      connection_printf_to_buf(conn, "513 Invalid argument\r\n");
      goto out;
    }
  }
  if (smartlist_len(port_cfgs) == 0) {
    connection_printf_to_buf(conn, "512 Missing 'Port' argument\r\n");
    goto out;
  } else if (auth_type == REND_NO_AUTH && auth_clients != NULL) {
    connection_printf_to_buf(conn, "512 No auth type specified\r\n");
    goto out;
  } else if (auth_type != REND_NO_AUTH && auth_clients == NULL) {
    connection_printf_to_buf(conn, "512 No auth clients specified\r\n");
    goto out;
  } else if ((auth_type == REND_BASIC_AUTH &&
              smartlist_len(auth_clients) > 512) ||
             (auth_type == REND_STEALTH_AUTH &&
              smartlist_len(auth_clients) > 16)) {
    connection_printf_to_buf(conn, "512 Too many auth clients\r\n");
    goto out;
  } else if (non_anonymous != rend_service_non_anonymous_mode_enabled(
                                                              get_options())) {
    /* If we failed, and the non-anonymous flag is set, Tor must be in
     * anonymous hidden service mode.
     * The error message changes based on the current Tor config:
     * 512 Tor is in anonymous hidden service mode
     * 512 Tor is in non-anonymous hidden service mode
     * (I've deliberately written them out in full here to aid searchability.)
     */
    connection_printf_to_buf(conn, "512 Tor is in %sanonymous hidden service "
                             "mode\r\n",
                             non_anonymous ? "" : "non-");
    goto out;
  }

  /* Parse the "keytype:keyblob" argument. */
  int hs_version = 0;
  add_onion_secret_key_t pk = { NULL };
  const char *key_new_alg = NULL;
  char *key_new_blob = NULL;
  char *err_msg = NULL;

  if (add_onion_helper_keyarg(smartlist_get(args, 0), discard_pk,
                              &key_new_alg, &key_new_blob, &pk, &hs_version,
                              &err_msg) < 0) {
    if (err_msg) {
      connection_write_str_to_buf(err_msg, conn);
      tor_free(err_msg);
    }
    goto out;
  }
  tor_assert(!err_msg);

  /* Hidden service version 3 don't have client authentication support so if
   * ClientAuth was given, send back an error. */
  if (hs_version == HS_VERSION_THREE && auth_clients) {
    connection_printf_to_buf(conn, "513 ClientAuth not supported\r\n");
    goto out;
  }

  /* Create the HS, using private key pk, client authentication auth_type,
   * the list of auth_clients, and port config port_cfg.
   * rend_service_add_ephemeral() will take ownership of pk and port_cfg,
   * regardless of success/failure.
   */
  char *service_id = NULL;
  int ret = add_onion_helper_add_service(hs_version, &pk, port_cfgs,
                                         max_streams,
                                         max_streams_close_circuit, auth_type,
                                         auth_clients, &service_id);
  port_cfgs = NULL; /* port_cfgs is now owned by the rendservice code. */
  auth_clients = NULL; /* so is auth_clients */
  switch (ret) {
  case RSAE_OKAY:
  {
    if (detach) {
      if (!detached_onion_services)
        detached_onion_services = smartlist_new();
      smartlist_add(detached_onion_services, service_id);
    } else {
      if (!conn->ephemeral_onion_services)
        conn->ephemeral_onion_services = smartlist_new();
      smartlist_add(conn->ephemeral_onion_services, service_id);
    }

    tor_assert(service_id);
    connection_printf_to_buf(conn, "250-ServiceID=%s\r\n", service_id);
    if (key_new_alg) {
      tor_assert(key_new_blob);
      connection_printf_to_buf(conn, "250-PrivateKey=%s:%s\r\n",
                               key_new_alg, key_new_blob);
    }
    if (auth_created_clients) {
      SMARTLIST_FOREACH(auth_created_clients, rend_authorized_client_t *, ac, {
        char *encoded = rend_auth_encode_cookie(ac->descriptor_cookie,
                                                auth_type);
        tor_assert(encoded);
        connection_printf_to_buf(conn, "250-ClientAuth=%s:%s\r\n",
                                 ac->client_name, encoded);
        memwipe(encoded, 0, strlen(encoded));
        tor_free(encoded);
      });
    }

    connection_printf_to_buf(conn, "250 OK\r\n");
    break;
  }
  case RSAE_BADPRIVKEY:
    connection_printf_to_buf(conn, "551 Failed to generate onion address\r\n");
    break;
  case RSAE_ADDREXISTS:
    connection_printf_to_buf(conn, "550 Onion address collision\r\n");
    break;
  case RSAE_BADVIRTPORT:
    connection_printf_to_buf(conn, "512 Invalid VIRTPORT/TARGET\r\n");
    break;
  case RSAE_BADAUTH:
    connection_printf_to_buf(conn, "512 Invalid client authorization\r\n");
    break;
  case RSAE_INTERNAL: /* FALLSTHROUGH */
  default:
    connection_printf_to_buf(conn, "551 Failed to add Onion Service\r\n");
  }
  if (key_new_blob) {
    memwipe(key_new_blob, 0, strlen(key_new_blob));
    tor_free(key_new_blob);
  }

 out:
  if (port_cfgs) {
    SMARTLIST_FOREACH(port_cfgs, rend_service_port_config_t*, p,
                      rend_service_port_config_free(p));
    smartlist_free(port_cfgs);
  }

  if (auth_clients) {
    SMARTLIST_FOREACH(auth_clients, rend_authorized_client_t *, ac,
                      rend_authorized_client_free(ac));
    smartlist_free(auth_clients);
  }
  if (auth_created_clients) {
    // Do not free entries; they are the same as auth_clients
    smartlist_free(auth_created_clients);
  }

  SMARTLIST_FOREACH(args, char *, cp, {
    memwipe(cp, 0, strlen(cp));
    tor_free(cp);
  });
  smartlist_free(args);
  return 0;
}

/** Helper function to handle parsing the KeyType:KeyBlob argument to the
 * ADD_ONION command. Return a new crypto_pk_t and if a new key was generated
 * and the private key not discarded, the algorithm and serialized private key,
 * or NULL and an optional control protocol error message on failure.  The
 * caller is responsible for freeing the returned key_new_blob and err_msg.
 *
 * Note: The error messages returned are deliberately vague to avoid echoing
 * key material.
 */
STATIC int
add_onion_helper_keyarg(const char *arg, int discard_pk,
                        const char **key_new_alg_out, char **key_new_blob_out,
                        add_onion_secret_key_t *decoded_key, int *hs_version,
                        char **err_msg_out)
{
  smartlist_t *key_args = smartlist_new();
  crypto_pk_t *pk = NULL;
  const char *key_new_alg = NULL;
  char *key_new_blob = NULL;
  char *err_msg = NULL;
  int ret = -1;

  smartlist_split_string(key_args, arg, ":", SPLIT_IGNORE_BLANK, 0);
  if (smartlist_len(key_args) != 2) {
    err_msg = tor_strdup("512 Invalid key type/blob\r\n");
    goto err;
  }

  /* The format is "KeyType:KeyBlob". */
  static const char *key_type_new = "NEW";
  static const char *key_type_best = "BEST";
  static const char *key_type_rsa1024 = "RSA1024";
  static const char *key_type_ed25519_v3 = "ED25519-V3";

  const char *key_type = smartlist_get(key_args, 0);
  const char *key_blob = smartlist_get(key_args, 1);

  if (!strcasecmp(key_type_rsa1024, key_type)) {
    /* "RSA:<Base64 Blob>" - Loading a pre-existing RSA1024 key. */
    pk = crypto_pk_base64_decode_private(key_blob, strlen(key_blob));
    if (!pk) {
      err_msg = tor_strdup("512 Failed to decode RSA key\r\n");
      goto err;
    }
    if (crypto_pk_num_bits(pk) != PK_BYTES*8) {
      crypto_pk_free(pk);
      err_msg = tor_strdup("512 Invalid RSA key size\r\n");
      goto err;
    }
    decoded_key->v2 = pk;
    *hs_version = HS_VERSION_TWO;
  } else if (!strcasecmp(key_type_ed25519_v3, key_type)) {
    /* "ED25519-V3:<Base64 Blob>" - Loading a pre-existing ed25519 key. */
    ed25519_secret_key_t *sk = tor_malloc_zero(sizeof(*sk));
    if (base64_decode((char *) sk->seckey, sizeof(sk->seckey), key_blob,
                      strlen(key_blob)) != sizeof(sk->seckey)) {
      tor_free(sk);
      err_msg = tor_strdup("512 Failed to decode ED25519-V3 key\r\n");
      goto err;
    }
    decoded_key->v3 = sk;
    *hs_version = HS_VERSION_THREE;
  } else if (!strcasecmp(key_type_new, key_type)) {
    /* "NEW:<Algorithm>" - Generating a new key, blob as algorithm. */
    if (!strcasecmp(key_type_rsa1024, key_blob) ||
        !strcasecmp(key_type_best, key_blob)) {
      /* "RSA1024", RSA 1024 bit, also currently "BEST" by default. */
      pk = crypto_pk_new();
      if (crypto_pk_generate_key(pk)) {
        tor_asprintf(&err_msg, "551 Failed to generate %s key\r\n",
                     key_type_rsa1024);
        goto err;
      }
      if (!discard_pk) {
        if (crypto_pk_base64_encode_private(pk, &key_new_blob)) {
          crypto_pk_free(pk);
          tor_asprintf(&err_msg, "551 Failed to encode %s key\r\n",
                       key_type_rsa1024);
          goto err;
        }
        key_new_alg = key_type_rsa1024;
      }
      decoded_key->v2 = pk;
      *hs_version = HS_VERSION_TWO;
    } else if (!strcasecmp(key_type_ed25519_v3, key_blob)) {
      ed25519_secret_key_t *sk = tor_malloc_zero(sizeof(*sk));
      if (ed25519_secret_key_generate(sk, 1) < 0) {
        tor_free(sk);
        tor_asprintf(&err_msg, "551 Failed to generate %s key\r\n",
                     key_type_ed25519_v3);
        goto err;
      }
      if (!discard_pk) {
        ssize_t len = base64_encode_size(sizeof(sk->seckey), 0) + 1;
        key_new_blob = tor_malloc_zero(len);
        if (base64_encode(key_new_blob, len, (const char *) sk->seckey,
                          sizeof(sk->seckey), 0) != (len - 1)) {
          tor_free(sk);
          tor_free(key_new_blob);
          tor_asprintf(&err_msg, "551 Failed to encode %s key\r\n",
                       key_type_ed25519_v3);
          goto err;
        }
        key_new_alg = key_type_ed25519_v3;
      }
      decoded_key->v3 = sk;
      *hs_version = HS_VERSION_THREE;
    } else {
      err_msg = tor_strdup("513 Invalid key type\r\n");
      goto err;
    }
  } else {
    err_msg = tor_strdup("513 Invalid key type\r\n");
    goto err;
  }

  /* Succeeded in loading or generating a private key. */
  ret = 0;

 err:
  SMARTLIST_FOREACH(key_args, char *, cp, {
    memwipe(cp, 0, strlen(cp));
    tor_free(cp);
  });
  smartlist_free(key_args);

  if (err_msg_out) {
    *err_msg_out = err_msg;
  } else {
    tor_free(err_msg);
  }
  *key_new_alg_out = key_new_alg;
  *key_new_blob_out = key_new_blob;

  return ret;
}

/** Helper function to handle parsing a ClientAuth argument to the
 * ADD_ONION command.  Return a new rend_authorized_client_t, or NULL
 * and an optional control protocol error message on failure.  The
 * caller is responsible for freeing the returned auth_client and err_msg.
 *
 * If 'created' is specified, it will be set to 1 when a new cookie has
 * been generated.
 */
STATIC rend_authorized_client_t *
add_onion_helper_clientauth(const char *arg, int *created, char **err_msg)
{
  int ok = 0;

  tor_assert(arg);
  tor_assert(created);
  tor_assert(err_msg);
  *err_msg = NULL;

  smartlist_t *auth_args = smartlist_new();
  rend_authorized_client_t *client =
    tor_malloc_zero(sizeof(rend_authorized_client_t));
  smartlist_split_string(auth_args, arg, ":", 0, 0);
  if (smartlist_len(auth_args) < 1 || smartlist_len(auth_args) > 2) {
    *err_msg = tor_strdup("512 Invalid ClientAuth syntax\r\n");
    goto err;
  }
  client->client_name = tor_strdup(smartlist_get(auth_args, 0));
  if (smartlist_len(auth_args) == 2) {
    char *decode_err_msg = NULL;
    if (rend_auth_decode_cookie(smartlist_get(auth_args, 1),
                                client->descriptor_cookie,
                                NULL, &decode_err_msg) < 0) {
      tor_assert(decode_err_msg);
      tor_asprintf(err_msg, "512 %s\r\n", decode_err_msg);
      tor_free(decode_err_msg);
      goto err;
    }
    *created = 0;
  } else {
    crypto_rand((char *) client->descriptor_cookie, REND_DESC_COOKIE_LEN);
    *created = 1;
  }

  if (!rend_valid_client_name(client->client_name)) {
    *err_msg = tor_strdup("512 Invalid name in ClientAuth\r\n");
    goto err;
  }

  ok = 1;
 err:
  SMARTLIST_FOREACH(auth_args, char *, item, tor_free(item));
  smartlist_free(auth_args);
  if (!ok) {
    rend_authorized_client_free(client);
    client = NULL;
  }
  return client;
}

/** Called when we get a DEL_ONION command; parse the body, and remove
 * the existing ephemeral Onion Service. */
static int
handle_control_del_onion(control_connection_t *conn,
                          uint32_t len,
                          const char *body)
{
  int hs_version = 0;
  smartlist_t *args;
  (void) len; /* body is nul-terminated; it's safe to ignore the length */
  args = getargs_helper("DEL_ONION", conn, body, 1, 1);
  if (!args)
    return 0;

  const char *service_id = smartlist_get(args, 0);
  if (rend_valid_v2_service_id(service_id)) {
    hs_version = HS_VERSION_TWO;
  } else if (hs_address_is_valid(service_id)) {
    hs_version = HS_VERSION_THREE;
  } else {
    connection_printf_to_buf(conn, "512 Malformed Onion Service id\r\n");
    goto out;
  }

  /* Determine if the onion service belongs to this particular control
   * connection, or if it is in the global list of detached services.  If it
   * is in neither, either the service ID is invalid in some way, or it
   * explicitly belongs to a different control connection, and an error
   * should be returned.
   */
  smartlist_t *services[2] = {
    conn->ephemeral_onion_services,
    detached_onion_services
  };
  smartlist_t *onion_services = NULL;
  int idx = -1;
  for (size_t i = 0; i < ARRAY_LENGTH(services); i++) {
    idx = smartlist_string_pos(services[i], service_id);
    if (idx != -1) {
      onion_services = services[i];
      break;
    }
  }
  if (onion_services == NULL) {
    connection_printf_to_buf(conn, "552 Unknown Onion Service id\r\n");
  } else {
    int ret = -1;
    switch (hs_version) {
    case HS_VERSION_TWO:
      ret = rend_service_del_ephemeral(service_id);
      break;
    case HS_VERSION_THREE:
      ret = hs_service_del_ephemeral(service_id);
      break;
    default:
      /* The ret value will be -1 thus hitting the warning below. This should
       * never happen because of the check at the start of the function. */
      break;
    }
    if (ret < 0) {
      /* This should *NEVER* fail, since the service is on either the
       * per-control connection list, or the global one.
       */
      log_warn(LD_BUG, "Failed to remove Onion Service %s.",
               escaped(service_id));
      tor_fragile_assert();
    }

    /* Remove/scrub the service_id from the appropriate list. */
    char *cp = smartlist_get(onion_services, idx);
    smartlist_del(onion_services, idx);
    memwipe(cp, 0, strlen(cp));
    tor_free(cp);

    send_control_done(conn);
  }

 out:
  SMARTLIST_FOREACH(args, char *, cp, {
    memwipe(cp, 0, strlen(cp));
    tor_free(cp);
  });
  smartlist_free(args);
  return 0;
}

/** Called when <b>conn</b> has no more bytes left on its outbuf. */
int
connection_control_finished_flushing(control_connection_t *conn)
{
  tor_assert(conn);
  return 0;
}

/** Called when <b>conn</b> has gotten its socket closed. */
int
connection_control_reached_eof(control_connection_t *conn)
{
  tor_assert(conn);

  log_info(LD_CONTROL,"Control connection reached EOF. Closing.");
  connection_mark_for_close(TO_CONN(conn));
  return 0;
}

/** Shut down this Tor instance in the same way that SIGINT would, but
 * with a log message appropriate for the loss of an owning controller. */
static void
lost_owning_controller(const char *owner_type, const char *loss_manner)
{
  log_notice(LD_CONTROL, "Owning controller %s has %s -- exiting now.",
             owner_type, loss_manner);

  activate_signal(SIGTERM);
}

/** Called when <b>conn</b> is being freed. */
void
connection_control_closed(control_connection_t *conn)
{
  tor_assert(conn);

  conn->event_mask = 0;
  control_update_global_event_mask();

  /* Close all ephemeral Onion Services if any.
   * The list and it's contents are scrubbed/freed in connection_free_.
   */
  if (conn->ephemeral_onion_services) {
    SMARTLIST_FOREACH_BEGIN(conn->ephemeral_onion_services, char *, cp) {
      if (rend_valid_v2_service_id(cp)) {
        rend_service_del_ephemeral(cp);
      } else if (hs_address_is_valid(cp)) {
        hs_service_del_ephemeral(cp);
      } else {
        /* An invalid .onion in our list should NEVER happen */
        tor_fragile_assert();
      }
    } SMARTLIST_FOREACH_END(cp);
  }

  if (conn->is_owning_control_connection) {
    lost_owning_controller("connection", "closed");
  }
}

/** Return true iff <b>cmd</b> is allowable (or at least forgivable) at this
 * stage of the protocol. */
static int
is_valid_initial_command(control_connection_t *conn, const char *cmd)
{
  if (conn->base_.state == CONTROL_CONN_STATE_OPEN)
    return 1;
  if (!strcasecmp(cmd, "PROTOCOLINFO"))
    return (!conn->have_sent_protocolinfo &&
            conn->safecookie_client_hash == NULL);
  if (!strcasecmp(cmd, "AUTHCHALLENGE"))
    return (conn->safecookie_client_hash == NULL);
  if (!strcasecmp(cmd, "AUTHENTICATE") ||
      !strcasecmp(cmd, "QUIT"))
    return 1;
  return 0;
}

/** Do not accept any control command of more than 1MB in length.  Anything
 * that needs to be anywhere near this long probably means that one of our
 * interfaces is broken. */
#define MAX_COMMAND_LINE_LENGTH (1024*1024)

/** Wrapper around peek_buf_has_control0 command: presents the same
 * interface as that underlying functions, but takes a connection_t intead of
 * a buf_t.
 */
static int
peek_connection_has_control0_command(connection_t *conn)
{
  return peek_buf_has_control0_command(conn->inbuf);
}

static int
peek_connection_has_http_command(connection_t *conn)
{
  return peek_buf_has_http_command(conn->inbuf);
}

static const char CONTROLPORT_IS_NOT_AN_HTTP_PROXY_MSG[] =
  "HTTP/1.0 501 Tor ControlPort is not an HTTP proxy"
  "\r\nContent-Type: text/html; charset=iso-8859-1\r\n\r\n"
  "<html>\n"
  "<head>\n"
  "<title>Tor's ControlPort is not an HTTP proxy</title>\n"
  "</head>\n"
  "<body>\n"
  "<h1>Tor's ControlPort is not an HTTP proxy</h1>\n"
  "<p>\n"
  "It appears you have configured your web browser to use Tor's control port"
  " as an HTTP proxy.\n"
  "This is not correct: Tor's default SOCKS proxy port is 9050.\n"
  "Please configure your client accordingly.\n"
  "</p>\n"
  "<p>\n"
  "See <a href=\"https://www.torproject.org/documentation.html\">"
  "https://www.torproject.org/documentation.html</a> for more "
  "information.\n"
  "<!-- Plus this comment, to make the body response more than 512 bytes, so "
  "     IE will be willing to display it. Comment comment comment comment "
  "     comment comment comment comment comment comment comment comment.-->\n"
  "</p>\n"
  "</body>\n"
  "</html>\n";

/** Called when data has arrived on a v1 control connection: Try to fetch
 * commands from conn->inbuf, and execute them.
 */
int
connection_control_process_inbuf(control_connection_t *conn)
{
  size_t data_len;
  uint32_t cmd_data_len;
  int cmd_len;
  char *args;

  tor_assert(conn);
  tor_assert(conn->base_.state == CONTROL_CONN_STATE_OPEN ||
             conn->base_.state == CONTROL_CONN_STATE_NEEDAUTH);

  if (!conn->incoming_cmd) {
    conn->incoming_cmd = tor_malloc(1024);
    conn->incoming_cmd_len = 1024;
    conn->incoming_cmd_cur_len = 0;
  }

  if (conn->base_.state == CONTROL_CONN_STATE_NEEDAUTH &&
      peek_connection_has_control0_command(TO_CONN(conn))) {
    /* Detect v0 commands and send a "no more v0" message. */
    size_t body_len;
    char buf[128];
    set_uint16(buf+2, htons(0x0000)); /* type == error */
    set_uint16(buf+4, htons(0x0001)); /* code == internal error */
    strlcpy(buf+6, "The v0 control protocol is not supported by Tor 0.1.2.17 "
            "and later; upgrade your controller.",
            sizeof(buf)-6);
    body_len = 2+strlen(buf+6)+2; /* code, msg, nul. */
    set_uint16(buf+0, htons(body_len));
    connection_buf_add(buf, 4+body_len, TO_CONN(conn));

    connection_mark_and_flush(TO_CONN(conn));
    return 0;
  }

  /* If the user has the HTTP proxy port and the control port confused. */
  if (conn->base_.state == CONTROL_CONN_STATE_NEEDAUTH &&
      peek_connection_has_http_command(TO_CONN(conn))) {
    connection_write_str_to_buf(CONTROLPORT_IS_NOT_AN_HTTP_PROXY_MSG, conn);
    log_notice(LD_CONTROL, "Received HTTP request on ControlPort");
    connection_mark_and_flush(TO_CONN(conn));
    return 0;
  }

 again:
  while (1) {
    size_t last_idx;
    int r;
    /* First, fetch a line. */
    do {
      data_len = conn->incoming_cmd_len - conn->incoming_cmd_cur_len;
      r = connection_buf_get_line(TO_CONN(conn),
                              conn->incoming_cmd+conn->incoming_cmd_cur_len,
                              &data_len);
      if (r == 0)
        /* Line not all here yet. Wait. */
        return 0;
      else if (r == -1) {
        if (data_len + conn->incoming_cmd_cur_len > MAX_COMMAND_LINE_LENGTH) {
          connection_write_str_to_buf("500 Line too long.\r\n", conn);
          connection_stop_reading(TO_CONN(conn));
          connection_mark_and_flush(TO_CONN(conn));
        }
        while (conn->incoming_cmd_len < data_len+conn->incoming_cmd_cur_len)
          conn->incoming_cmd_len *= 2;
        conn->incoming_cmd = tor_realloc(conn->incoming_cmd,
                                         conn->incoming_cmd_len);
      }
    } while (r != 1);

    tor_assert(data_len);

    last_idx = conn->incoming_cmd_cur_len;
    conn->incoming_cmd_cur_len += (int)data_len;

    /* We have appended a line to incoming_cmd.  Is the command done? */
    if (last_idx == 0 && *conn->incoming_cmd != '+')
      /* One line command, didn't start with '+'. */
      break;
    /* XXXX this code duplication is kind of dumb. */
    if (last_idx+3 == conn->incoming_cmd_cur_len &&
        tor_memeq(conn->incoming_cmd + last_idx, ".\r\n", 3)) {
      /* Just appended ".\r\n"; we're done. Remove it. */
      conn->incoming_cmd[last_idx] = '\0';
      conn->incoming_cmd_cur_len -= 3;
      break;
    } else if (last_idx+2 == conn->incoming_cmd_cur_len &&
               tor_memeq(conn->incoming_cmd + last_idx, ".\n", 2)) {
      /* Just appended ".\n"; we're done. Remove it. */
      conn->incoming_cmd[last_idx] = '\0';
      conn->incoming_cmd_cur_len -= 2;
      break;
    }
    /* Otherwise, read another line. */
  }
  data_len = conn->incoming_cmd_cur_len;
  /* Okay, we now have a command sitting on conn->incoming_cmd. See if we
   * recognize it.
   */
  cmd_len = 0;
  while ((size_t)cmd_len < data_len
         && !TOR_ISSPACE(conn->incoming_cmd[cmd_len]))
    ++cmd_len;

  conn->incoming_cmd[cmd_len]='\0';
  args = conn->incoming_cmd+cmd_len+1;
  tor_assert(data_len>(size_t)cmd_len);
  data_len -= (cmd_len+1); /* skip the command and NUL we added after it */
  while (TOR_ISSPACE(*args)) {
    ++args;
    --data_len;
  }

  /* If the connection is already closing, ignore further commands */
  if (TO_CONN(conn)->marked_for_close) {
    return 0;
  }

  /* Otherwise, Quit is always valid. */
  if (!strcasecmp(conn->incoming_cmd, "QUIT")) {
    connection_write_str_to_buf("250 closing connection\r\n", conn);
    connection_mark_and_flush(TO_CONN(conn));
    return 0;
  }

  if (conn->base_.state == CONTROL_CONN_STATE_NEEDAUTH &&
      !is_valid_initial_command(conn, conn->incoming_cmd)) {
    connection_write_str_to_buf("514 Authentication required.\r\n", conn);
    connection_mark_for_close(TO_CONN(conn));
    return 0;
  }

  if (data_len >= UINT32_MAX) {
    connection_write_str_to_buf("500 A 4GB command? Nice try.\r\n", conn);
    connection_mark_for_close(TO_CONN(conn));
    return 0;
  }

  /* XXXX Why is this not implemented as a table like the GETINFO
   * items are?  Even handling the plus signs at the beginnings of
   * commands wouldn't be very hard with proper macros. */
  cmd_data_len = (uint32_t)data_len;
  if (!strcasecmp(conn->incoming_cmd, "SETCONF")) {
    if (handle_control_setconf(conn, cmd_data_len, args))
      return -1;
  } else if (!strcasecmp(conn->incoming_cmd, "RESETCONF")) {
    if (handle_control_resetconf(conn, cmd_data_len, args))
      return -1;
  } else if (!strcasecmp(conn->incoming_cmd, "GETCONF")) {
    if (handle_control_getconf(conn, cmd_data_len, args))
      return -1;
  } else if (!strcasecmp(conn->incoming_cmd, "+LOADCONF")) {
    if (handle_control_loadconf(conn, cmd_data_len, args))
      return -1;
  } else if (!strcasecmp(conn->incoming_cmd, "SETEVENTS")) {
    if (handle_control_setevents(conn, cmd_data_len, args))
      return -1;
  } else if (!strcasecmp(conn->incoming_cmd, "AUTHENTICATE")) {
    if (handle_control_authenticate(conn, cmd_data_len, args))
      return -1;
  } else if (!strcasecmp(conn->incoming_cmd, "SAVECONF")) {
    if (handle_control_saveconf(conn, cmd_data_len, args))
      return -1;
  } else if (!strcasecmp(conn->incoming_cmd, "SIGNAL")) {
    if (handle_control_signal(conn, cmd_data_len, args))
      return -1;
  } else if (!strcasecmp(conn->incoming_cmd, "TAKEOWNERSHIP")) {
    if (handle_control_takeownership(conn, cmd_data_len, args))
      return -1;
  } else if (!strcasecmp(conn->incoming_cmd, "DROPOWNERSHIP")) {
    if (handle_control_dropownership(conn, cmd_data_len, args))
      return -1;
  } else if (!strcasecmp(conn->incoming_cmd, "MAPADDRESS")) {
    if (handle_control_mapaddress(conn, cmd_data_len, args))
      return -1;
  } else if (!strcasecmp(conn->incoming_cmd, "GETINFO")) {
    if (handle_control_getinfo(conn, cmd_data_len, args))
      return -1;
  } else if (!strcasecmp(conn->incoming_cmd, "EXTENDCIRCUIT")) {
    if (handle_control_extendcircuit(conn, cmd_data_len, args))
      return -1;
  } else if (!strcasecmp(conn->incoming_cmd, "SETCIRCUITPURPOSE")) {
    if (handle_control_setcircuitpurpose(conn, cmd_data_len, args))
      return -1;
  } else if (!strcasecmp(conn->incoming_cmd, "SETROUTERPURPOSE")) {
    connection_write_str_to_buf("511 SETROUTERPURPOSE is obsolete.\r\n", conn);
  } else if (!strcasecmp(conn->incoming_cmd, "ATTACHSTREAM")) {
    if (handle_control_attachstream(conn, cmd_data_len, args))
      return -1;
  } else if (!strcasecmp(conn->incoming_cmd, "+POSTDESCRIPTOR")) {
    if (handle_control_postdescriptor(conn, cmd_data_len, args))
      return -1;
  } else if (!strcasecmp(conn->incoming_cmd, "REDIRECTSTREAM")) {
    if (handle_control_redirectstream(conn, cmd_data_len, args))
      return -1;
  } else if (!strcasecmp(conn->incoming_cmd, "CLOSESTREAM")) {
    if (handle_control_closestream(conn, cmd_data_len, args))
      return -1;
  } else if (!strcasecmp(conn->incoming_cmd, "CLOSECIRCUIT")) {
    if (handle_control_closecircuit(conn, cmd_data_len, args))
      return -1;
  } else if (!strcasecmp(conn->incoming_cmd, "USEFEATURE")) {
    if (handle_control_usefeature(conn, cmd_data_len, args))
      return -1;
  } else if (!strcasecmp(conn->incoming_cmd, "RESOLVE")) {
    if (handle_control_resolve(conn, cmd_data_len, args))
      return -1;
  } else if (!strcasecmp(conn->incoming_cmd, "PROTOCOLINFO")) {
    if (handle_control_protocolinfo(conn, cmd_data_len, args))
      return -1;
  } else if (!strcasecmp(conn->incoming_cmd, "AUTHCHALLENGE")) {
    if (handle_control_authchallenge(conn, cmd_data_len, args))
      return -1;
  } else if (!strcasecmp(conn->incoming_cmd, "DROPGUARDS")) {
    if (handle_control_dropguards(conn, cmd_data_len, args))
      return -1;
  } else if (!strcasecmp(conn->incoming_cmd, "HSFETCH")) {
    if (handle_control_hsfetch(conn, cmd_data_len, args))
      return -1;
  } else if (!strcasecmp(conn->incoming_cmd, "+HSPOST")) {
    if (handle_control_hspost(conn, cmd_data_len, args))
      return -1;
  } else if (!strcasecmp(conn->incoming_cmd, "ADD_ONION")) {
    int ret = handle_control_add_onion(conn, cmd_data_len, args);
    memwipe(args, 0, cmd_data_len); /* Scrub the private key. */
    if (ret)
      return -1;
  } else if (!strcasecmp(conn->incoming_cmd, "DEL_ONION")) {
    int ret = handle_control_del_onion(conn, cmd_data_len, args);
    memwipe(args, 0, cmd_data_len); /* Scrub the service id/pk. */
    if (ret)
      return -1;
  } else {
    connection_printf_to_buf(conn, "510 Unrecognized command \"%s\"\r\n",
                             conn->incoming_cmd);
  }

  conn->incoming_cmd_cur_len = 0;
  goto again;
}
/** Cached liveness for network liveness events and GETINFO
 */

static int network_is_live = 0;

int
get_cached_network_liveness(void)
{
  return network_is_live;
}

void
set_cached_network_liveness(int liveness)
{
  network_is_live = liveness;
}

/** Helper: Return a newly allocated string containing a path to the
 * file where we store our authentication cookie. */
char *
get_controller_cookie_file_name(void)
{
  const or_options_t *options = get_options();
  if (options->CookieAuthFile && strlen(options->CookieAuthFile)) {
    return tor_strdup(options->CookieAuthFile);
  } else {
    return get_datadir_fname("control_auth_cookie");
  }
}

/* Initialize the cookie-based authentication system of the
 * ControlPort. If <b>enabled</b> is 0, then disable the cookie
 * authentication system.  */
int
init_control_cookie_authentication(int enabled)
{
  char *fname = NULL;
  int retval;

  if (!enabled) {
    authentication_cookie_is_set = 0;
    return 0;
  }

  fname = get_controller_cookie_file_name();
  retval = init_cookie_authentication(fname, "", /* no header */
                                      AUTHENTICATION_COOKIE_LEN,
                                   get_options()->CookieAuthFileGroupReadable,
                                      &authentication_cookie,
                                      &authentication_cookie_is_set);
  tor_free(fname);
  return retval;
}

/** A copy of the process specifier of Tor's owning controller, or
 * NULL if this Tor instance is not currently owned by a process. */
static char *owning_controller_process_spec = NULL;

/** A process-termination monitor for Tor's owning controller, or NULL
 * if this Tor instance is not currently owned by a process. */
static tor_process_monitor_t *owning_controller_process_monitor = NULL;

/** Process-termination monitor callback for Tor's owning controller
 * process. */
static void
owning_controller_procmon_cb(void *unused)
{
  (void)unused;

  lost_owning_controller("process", "vanished");
}

/** Set <b>process_spec</b> as Tor's owning controller process.
 * Exit on failure. */
void
monitor_owning_controller_process(const char *process_spec)
{
  const char *msg;

  tor_assert((owning_controller_process_spec == NULL) ==
             (owning_controller_process_monitor == NULL));

  if (owning_controller_process_spec != NULL) {
    if ((process_spec != NULL) && !strcmp(process_spec,
                                          owning_controller_process_spec)) {
      /* Same process -- return now, instead of disposing of and
       * recreating the process-termination monitor. */
      return;
    }

    /* We are currently owned by a process, and we should no longer be
     * owned by it.  Free the process-termination monitor. */
    tor_process_monitor_free(owning_controller_process_monitor);
    owning_controller_process_monitor = NULL;

    tor_free(owning_controller_process_spec);
    owning_controller_process_spec = NULL;
  }

  tor_assert((owning_controller_process_spec == NULL) &&
             (owning_controller_process_monitor == NULL));

  if (process_spec == NULL)
    return;

  owning_controller_process_spec = tor_strdup(process_spec);
  owning_controller_process_monitor =
    tor_process_monitor_new(tor_libevent_get_base(),
                            owning_controller_process_spec,
                            LD_CONTROL,
                            owning_controller_procmon_cb, NULL,
                            &msg);

  if (owning_controller_process_monitor == NULL) {
    log_err(LD_BUG, "Couldn't create process-termination monitor for "
            "owning controller: %s.  Exiting.",
            msg);
    owning_controller_process_spec = NULL;
    tor_shutdown_event_loop_and_exit(1);
  }
}

/** Return a longname the node whose identity is <b>id_digest</b>. If
 * node_get_by_id() returns NULL, base 16 encoding of <b>id_digest</b> is
 * returned instead.
 *
 * This function is not thread-safe.  Each call to this function invalidates
 * previous values returned by this function.
 */
MOCK_IMPL(const char *,
node_describe_longname_by_id,(const char *id_digest))
{
  static char longname[MAX_VERBOSE_NICKNAME_LEN+1];
  node_get_verbose_nickname_by_id(id_digest, longname);
  return longname;
}

/** Free any leftover allocated memory of the control.c subsystem. */
void
control_free_all(void)
{
  control_events_free_all();

  if (authentication_cookie) /* Free the auth cookie */
    tor_free(authentication_cookie);
  if (detached_onion_services) { /* Free the detached onion services */
    SMARTLIST_FOREACH(detached_onion_services, char *, cp, tor_free(cp));
    smartlist_free(detached_onion_services);
  }
  control_event_bootstrap_reset();
  authentication_cookie_is_set = 0;
}
