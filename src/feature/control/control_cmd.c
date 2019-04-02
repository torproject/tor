/* Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2019, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file control_cmd.c
 * \brief Implement various commands for Tor's control-socket interface.
 **/

#define CONTROL_MODULE_PRIVATE
#define CONTROL_CMD_PRIVATE
#define CONTROL_EVENTS_PRIVATE

#include "core/or/or.h"
#include "app/config/config.h"
#include "app/config/confparse.h"
#include "app/main/main.h"
#include "core/mainloop/connection.h"
#include "core/or/circuitbuild.h"
#include "core/or/circuitlist.h"
#include "core/or/circuituse.h"
#include "core/or/connection_edge.h"
#include "feature/client/addressmap.h"
#include "feature/client/dnsserv.h"
#include "feature/client/entrynodes.h"
#include "feature/control/control.h"
#include "feature/control/control_auth.h"
#include "feature/control/control_cmd.h"
#include "feature/control/control_events.h"
#include "feature/control/control_fmt.h"
#include "feature/control/control_getinfo.h"
#include "feature/hs/hs_control.h"
#include "feature/nodelist/nodelist.h"
#include "feature/nodelist/routerinfo.h"
#include "feature/nodelist/routerlist.h"
#include "feature/rend/rendclient.h"
#include "feature/rend/rendcommon.h"
#include "feature/rend/rendparse.h"
#include "feature/rend/rendservice.h"
#include "lib/crypt_ops/crypto_rand.h"
#include "lib/crypt_ops/crypto_util.h"
#include "lib/encoding/confline.h"

#include "core/or/cpath_build_state_st.h"
#include "core/or/entry_connection_st.h"
#include "core/or/origin_circuit_st.h"
#include "core/or/socks_request_st.h"
#include "feature/control/control_cmd_args_st.h"
#include "feature/control/control_connection_st.h"
#include "feature/nodelist/node_st.h"
#include "feature/nodelist/routerinfo_st.h"
#include "feature/rend/rend_authorized_client_st.h"
#include "feature/rend/rend_encoded_v2_service_descriptor_st.h"
#include "feature/rend/rend_service_descriptor_st.h"

static int control_setconf_helper(control_connection_t *conn, uint32_t len,
                                  char *body,
                                  int use_defaults);

/** Yield true iff <b>s</b> is the state of a control_connection_t that has
 * finished authentication and is accepting commands. */
#define STATE_IS_OPEN(s) ((s) == CONTROL_CONN_STATE_OPEN)

/**
 * Release all storage held in <b>args</b>
 **/
void
control_cmd_args_free_(control_cmd_args_t *args)
{
  if (! args)
    return;

  if (args->args) {
    SMARTLIST_FOREACH(args->args, char *, c, tor_free(c));
    smartlist_free(args->args);
  }
  tor_free(args->object);

  tor_free(args);
}

/**
 * Helper: parse the arguments to a command according to <b>syntax</b>.  On
 * success, set *<b>error_out</b> to NULL and return a newly allocated
 * control_cmd_args_t.  On failure, set *<b>error_out</b> to newly allocated
 * error string, and return NULL.
 **/
STATIC control_cmd_args_t *
control_cmd_parse_args(const char *command,
                       const control_cmd_syntax_t *syntax,
                       size_t body_len,
                       const char *body,
                       char **error_out)
{
  *error_out = NULL;
  control_cmd_args_t *result = tor_malloc_zero(sizeof(control_cmd_args_t));
  const char *cmdline;
  char *cmdline_alloc = NULL;

  result->command = command;

  const char *eol = memchr(body, '\n', body_len);
  if (syntax->want_object) {
    if (! eol || (eol+1) == body+body_len) {
      *error_out = tor_strdup("Empty body");
      goto err;
    }
    cmdline_alloc = tor_memdup_nulterm(body, eol-body);
    cmdline = cmdline_alloc;
    ++eol;
    result->object_len = read_escaped_data(eol, (body+body_len)-eol,
                                           &result->object);
  } else {
    if (eol && (eol+1) != body+body_len) {
      *error_out = tor_strdup("Unexpected body");
      goto err;
    }
    cmdline = body;
  }

  result->args = smartlist_new();
  smartlist_split_string(result->args, cmdline, " ",
                         SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 0);
  size_t n_args = smartlist_len(result->args);
  if (n_args < syntax->min_args) {
    tor_asprintf(error_out, "Need at least %u argument(s)",
                 syntax->min_args);
    goto err;
  } else if (n_args > syntax->max_args) {
    tor_asprintf(error_out, "Cannot accept more than %u argument(s)",
                 syntax->max_args);
    goto err;
  }

  tor_assert_nonfatal(*error_out == NULL);
  goto done;
 err:
  tor_assert_nonfatal(*error_out != NULL);
  control_cmd_args_free(result);
 done:
  tor_free(cmdline_alloc);
  return result;
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
                       char *body)
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

/** The list of onion services that have been added via ADD_ONION that do not
 * belong to any particular control connection.
 */
static smartlist_t *detached_onion_services = NULL;

/**
 * Return a list of detached onion services, or NULL if none exist.
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

/**
 * Called when we get an obsolete command: tell the controller that it is
 * obsolete.
 */
static int
handle_control_obsolete(control_connection_t *conn,
                        uint32_t arg_len,
                        const char *args)
{
  (void)arg_len;
  (void)args;
  char *command = tor_strdup(conn->current_cmd);
  tor_strupper(command);
  connection_printf_to_buf(conn, "511 %s is obsolete.\r\n", command);
  tor_free(command);
  return 0;
}

/**
 * Selects an API to a controller command.  See handler_fn_t for the
 * possible types.
 **/
typedef enum handler_type_t {
  hnd_legacy,
  hnd_legacy_mut,
  hnd_parsed,
} handler_type_t;

/**
 * Union: a function pointer to a handler function for a controller command.
 *
 * This needs to be a union (rather than just a single pointer) since not
 * all controller commands have the same type.
 **/
typedef union handler_fn_t {
  /**
   * A "legacy" handler takes a command's arguments as a nul-terminated
   * string, and their length.  It may not change the contents of the
   * arguments.  If the command is a multiline one, then the arguments may
   * extend across multiple lines.
   */
  int (*legacy)(control_connection_t *conn,
                uint32_t arg_len,
                const char *args);
  /**
   * A "legacy_mut" handler is the same as a "legacy" one, except that it may
   * change the contents of the command's arguments -- for example, by
   * inserting NULs.  It may not deallocate them.
   */
  int (*legacy_mut)(control_connection_t *conn,
                    uint32_t arg_len,
                    char *args);

  /**
   * A "parsed" handler expects its arguments in a pre-parsed format, in
   * an immutable control_cmd_args_t *object.
   **/
  int (*parsed)(control_connection_t *conn,
                const control_cmd_args_t *args);
} handler_fn_t;

/**
 * Definition for a controller command.
 */
typedef struct control_cmd_def_t {
  /**
   * The name of the command. If the command is multiline, the name must
   * begin with "+".  This is not case-sensitive. */
  const char *name;
  /**
   * Which API to use when calling the handler function.
   */
  handler_type_t handler_type;
  /**
   * A function to execute the command.
   */
  handler_fn_t handler;
  /**
   * Zero or more CMD_FL_* flags, or'd together.
   */
  unsigned flags;
  /**
   * For parsed command: a syntax description.
   */
  const control_cmd_syntax_t *syntax;
} control_cmd_def_t;

/**
 * Indicates that the command's arguments are sensitive, and should be
 * memwiped after use.
 */
#define CMD_FL_WIPE (1u<<0)

#define SYNTAX_IGNORE { 0, UINT_MAX, false }

/** Macro: declare a command with a one-line argument, a given set of flags,
 * and a syntax definition.
 **/
#define ONE_LINE_(name, htype, flags, syntax)                   \
  { #name,                                                      \
      hnd_ ##htype,                                             \
      { .htype = handle_control_ ##name },                      \
      flags,                                                    \
      syntax,                                                   \
  }

/** Macro: declare a parsed command with a one-line argument, a given set of
 * flags, and a syntax definition.
 **/
#define ONE_LINE(name, htype, flags) \
  ONE_LINE_(name, htype, flags, NULL)
#define ONE_LINE_PARSED(name, flags, syntax) \
  ONE_LINE_(name, parsed, flags, syntax)

/**
 * Macro: declare a command with a multi-line argument and a given set of
 * flags.
 **/
#define MULTLINE(name, htype, flags)                            \
  { "+"#name,                                                   \
      hnd_ ##htype,                                             \
      { .htype = handle_control_ ##name },                      \
      flags,                                                    \
      NULL                                                      \
  }
/**
 * Macro: declare an obsolete command. (Obsolete commands give a different
 * error than non-existent ones.)
 **/
#define OBSOLETE(name)                          \
  { #name,                                      \
      hnd_legacy,                               \
      { .legacy = handle_control_obsolete },    \
      0,                                        \
      NULL,                                     \
  }

/**
 * An array defining all the recognized controller commands.
 **/
static const control_cmd_def_t CONTROL_COMMANDS[] =
{
  ONE_LINE(setconf, legacy_mut, 0),
  ONE_LINE(resetconf, legacy_mut, 0),
  ONE_LINE(getconf, legacy_mut, 0),
  MULTLINE(loadconf, legacy, 0),
  ONE_LINE(setevents, legacy, 0),
  ONE_LINE(authenticate, legacy, CMD_FL_WIPE),
  ONE_LINE(saveconf, legacy, 0),
  ONE_LINE(signal, legacy, 0),
  ONE_LINE(takeownership, legacy, 0),
  ONE_LINE(dropownership, legacy, 0),
  ONE_LINE(mapaddress, legacy, 0),
  ONE_LINE(getinfo, legacy, 0),
  ONE_LINE(extendcircuit, legacy, 0),
  ONE_LINE(setcircuitpurpose, legacy, 0),
  OBSOLETE(setrouterpurpose),
  ONE_LINE(attachstream, legacy, 0),
  MULTLINE(postdescriptor, legacy, 0),
  ONE_LINE(redirectstream, legacy, 0),
  ONE_LINE(closestream, legacy, 0),
  ONE_LINE(closecircuit, legacy, 0),
  ONE_LINE(usefeature, legacy, 0),
  ONE_LINE(resolve, legacy, 0),
  ONE_LINE(protocolinfo, legacy, 0),
  ONE_LINE(authchallenge, legacy, CMD_FL_WIPE),
  ONE_LINE(dropguards, legacy, 0),
  ONE_LINE(hsfetch, legacy, 0),
  MULTLINE(hspost, legacy, 0),
  ONE_LINE(add_onion, legacy, CMD_FL_WIPE),
  ONE_LINE(del_onion, legacy, CMD_FL_WIPE),
};

/**
 * The number of entries in CONTROL_COMMANDS.
 **/
static const size_t N_CONTROL_COMMANDS = ARRAY_LENGTH(CONTROL_COMMANDS);

/**
 * Run a single control command, as defined by a control_cmd_def_t,
 * with a given set of arguments.
 */
static int
handle_single_control_command(const control_cmd_def_t *def,
                              control_connection_t *conn,
                              uint32_t cmd_data_len,
                              char *args)
{
  int rv = 0;
  switch (def->handler_type) {
    case hnd_legacy:
      if (def->handler.legacy(conn, cmd_data_len, args))
        rv = -1;
      break;
    case hnd_legacy_mut:
      if (def->handler.legacy_mut(conn, cmd_data_len, args))
        rv = -1;
      break;
    case hnd_parsed: {
      control_cmd_args_t *parsed_args;
      char *err=NULL;
      tor_assert(def->syntax);
      parsed_args = control_cmd_parse_args(conn->current_cmd,
                                           def->syntax,
                                           cmd_data_len, args,
                                           &err);
      if (!parsed_args) {
        connection_printf_to_buf(conn,
                                 "512 Bad arguments to %s: %s\r\n",
                                 conn->current_cmd, err?err:"");
        tor_free(err);
      } else {
        if (BUG(err))
          tor_free(err);
        if (def->handler.parsed(conn, parsed_args))
          rv = 0;
        control_cmd_args_free(parsed_args);
      }
      break;
    }
    default:
      tor_assert_unreached();
  }

  if (def->flags & CMD_FL_WIPE)
    memwipe(args, 0, cmd_data_len);

  return rv;
}

/**
 * Run a given controller command, as selected by the current_cmd field of
 * <b>conn</b>.
 */
int
handle_control_command(control_connection_t *conn,
                       uint32_t cmd_data_len,
                       char *args)
{
  tor_assert(conn);
  tor_assert(args);
  tor_assert(args[cmd_data_len] == '\0');

  for (unsigned i = 0; i < N_CONTROL_COMMANDS; ++i) {
    const control_cmd_def_t *def = &CONTROL_COMMANDS[i];
    if (!strcasecmp(conn->current_cmd, def->name)) {
      return handle_single_control_command(def, conn, cmd_data_len, args);
    }
  }

  connection_printf_to_buf(conn, "510 Unrecognized command \"%s\"\r\n",
                           conn->current_cmd);

  return 0;
}

void
control_cmd_free_all(void)
{
  if (detached_onion_services) { /* Free the detached onion services */
    SMARTLIST_FOREACH(detached_onion_services, char *, cp, tor_free(cp));
    smartlist_free(detached_onion_services);
  }
}
