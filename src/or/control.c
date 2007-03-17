/* Copyright 2004-2007 Roger Dingledine, Nick Mathewson. */
/* See LICENSE for licensing information */
/* $Id$ */
const char control_c_id[] =
  "$Id$";

/**
 * \file control.c
 * \brief Implementation for Tor's control-socket interface.
 *   See control-spec.txt for full details on protocol.
 **/

#include "or.h"

/** Yield true iff <b>s</b> is the state of a control_connection_t that has
 * finished authentication and is accepting commands. */
#define STATE_IS_OPEN(s) ((s) == CONTROL_CONN_STATE_OPEN)

/* Recognized asynchronous event types.  It's okay to expand this list
 * because it is used both as a list of v0 event types, and as indices
 * into the bitfield to determine which controllers want which events.
 */
#define _EVENT_MIN             0x0001
#define EVENT_CIRCUIT_STATUS   0x0001
#define EVENT_STREAM_STATUS    0x0002
#define EVENT_OR_CONN_STATUS   0x0003
#define EVENT_BANDWIDTH_USED   0x0004
#define EVENT_LOG_OBSOLETE     0x0005 /* Can reclaim this. */
#define EVENT_NEW_DESC         0x0006
#define EVENT_DEBUG_MSG        0x0007
#define EVENT_INFO_MSG         0x0008
#define EVENT_NOTICE_MSG       0x0009
#define EVENT_WARN_MSG         0x000A
#define EVENT_ERR_MSG          0x000B
#define EVENT_ADDRMAP          0x000C
#define EVENT_AUTHDIR_NEWDESCS 0x000D
#define EVENT_DESCCHANGED      0x000E
#define EVENT_NS               0x000F
#define EVENT_STATUS_CLIENT    0x0010
#define EVENT_STATUS_SERVER    0x0011
#define EVENT_STATUS_GENERAL   0x0012
#define EVENT_GUARD            0x0013
#define EVENT_STREAM_BANDWIDTH_USED   0x0014
#define _EVENT_MAX             0x0014
/* If _EVENT_MAX ever hits 0x0020, we need to make the mask wider. */

/** Bitfield: The bit 1&lt;&lt;e is set if <b>any</b> open control
 * connection is interested in events of type <b>e</b>.  We use this
 * so that we can decide to skip generating event messages that nobody
 * has interest in without having to walk over the global connection
 * list to find out.
 **/
typedef uint32_t event_mask_t;
static event_mask_t global_event_mask1long = 0;
static event_mask_t global_event_mask1short = 0;

/** True iff we have disabled log messages from being sent to the controller */
static int disable_log_messages = 0;

/** Macro: true if any control connection is interested in events of type
 * <b>e</b>. */
#define EVENT_IS_INTERESTING(e) \
  ((global_event_mask1long|global_event_mask1short) & (1<<(e)))
#define EVENT_IS_INTERESTING1L(e) (global_event_mask1long & (1<<(e)))
#define EVENT_IS_INTERESTING1S(e) (global_event_mask1short & (1<<(e)))

/** If we're using cookie-type authentication, how long should our cookies be?
 */
#define AUTHENTICATION_COOKIE_LEN 32

/** If true, we've set authentication_cookie to a secret code and
 * stored it to disk. */
static int authentication_cookie_is_set = 0;
static char authentication_cookie[AUTHENTICATION_COOKIE_LEN];

#define SHORT_NAMES 1
#define LONG_NAMES 2
#define ALL_NAMES (SHORT_NAMES|LONG_NAMES)
#define EXTENDED_FORMAT 4
#define NONEXTENDED_FORMAT 8
#define ALL_FORMATS (EXTENDED_FORMAT|NONEXTENDED_FORMAT)
typedef int event_format_t;

static void connection_printf_to_buf(control_connection_t *conn,
                                     const char *format, ...)
  CHECK_PRINTF(2,3);
/*static*/ size_t write_escaped_data(const char *data, size_t len,
                                     int translate_newlines, char **out);
/*static*/ size_t read_escaped_data(const char *data, size_t len,
                                    int translate_newlines,  char **out);
static void send_control_done(control_connection_t *conn);
static void send_control_event(uint16_t event, event_format_t which,
                               const char *format, ...)
  CHECK_PRINTF(3,4);
static void send_control_event_extended(uint16_t event, event_format_t which,
                                         const char *format, ...)
  CHECK_PRINTF(3,4);
static int handle_control_setconf(control_connection_t *conn, uint32_t len,
                                  char *body);
static int handle_control_resetconf(control_connection_t *conn, uint32_t len,
                                    char *body);
static int handle_control_getconf(control_connection_t *conn, uint32_t len,
                                  const char *body);
static int handle_control_setevents(control_connection_t *conn, uint32_t len,
                                    const char *body);
static int handle_control_authenticate(control_connection_t *conn,
                                       uint32_t len,
                                       const char *body);
static int handle_control_saveconf(control_connection_t *conn, uint32_t len,
                                   const char *body);
static int handle_control_signal(control_connection_t *conn, uint32_t len,
                                 const char *body);
static int handle_control_mapaddress(control_connection_t *conn, uint32_t len,
                                     const char *body);
static char *list_getinfo_options(void);
static int handle_control_getinfo(control_connection_t *conn, uint32_t len,
                                  const char *body);
static int handle_control_extendcircuit(control_connection_t *conn,
                                        uint32_t len,
                                        const char *body);
static int handle_control_setpurpose(control_connection_t *conn,
                                     int for_circuits,
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
static int handle_control_usefeature(control_connection_t *conn,
                                     uint32_t len,
                                     const char *body);
static int write_stream_target_to_buf(edge_connection_t *conn, char *buf,
                                      size_t len);
static void orconn_target_get_name(int long_names, char *buf, size_t len,
                                   or_connection_t *conn);

/** Given a control event code for a message event, return the corresponding
 * log severity. */
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

/** Given a log severity, return the corresponding control event code. */
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

/** Set <b>global_event_mask*</b> to the bitwise OR of each live control
 * connection's event_mask field. */
void
control_update_global_event_mask(void)
{
  connection_t **conns;
  int n_conns, i;
  event_mask_t old_mask, new_mask;
  old_mask = global_event_mask1short;
  old_mask |= global_event_mask1long;

  global_event_mask1short = 0;
  global_event_mask1long = 0;
  get_connection_array(&conns, &n_conns);
  for (i = 0; i < n_conns; ++i) {
    if (conns[i]->type == CONN_TYPE_CONTROL &&
        STATE_IS_OPEN(conns[i]->state)) {
      control_connection_t *conn = TO_CONTROL_CONN(conns[i]);
      if (conn->use_long_names)
        global_event_mask1long |= conn->event_mask;
      else
        global_event_mask1short |= conn->event_mask;
    }
  }

  new_mask = global_event_mask1short;
  new_mask |= global_event_mask1long;

  /* Handle the aftermath.  Set up the log callback to tell us only what
   * we want to hear...*/
  control_adjust_event_log_severity();

  /* ...then, if we've started logging stream bw, clear the appropriate
   * fields. */
  if (! (old_mask & EVENT_STREAM_BANDWIDTH_USED) &&
      (new_mask & EVENT_STREAM_BANDWIDTH_USED)) {
    for (i = 0; i < n_conns; ++i) {
      if (conns[i]->type == CONN_TYPE_AP) {
        edge_connection_t *conn = TO_EDGE_CONN(conns[i]);
        conn->n_written = conn->n_read = 0;
      }
    }
  }
}

/** Adjust the log severities that result in control_event_logmsg being called
 * to match the severity of log messages that any controllers are interested
 * in. */
void
control_adjust_event_log_severity(void)
{
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
  if (EVENT_IS_INTERESTING(EVENT_LOG_OBSOLETE) ||
      EVENT_IS_INTERESTING(EVENT_STATUS_GENERAL)) {
    if (min_log_event > EVENT_NOTICE_MSG)
      min_log_event = EVENT_NOTICE_MSG;
    if (max_log_event < EVENT_ERR_MSG)
      max_log_event = EVENT_ERR_MSG;
  }
  change_callback_log_severity(event_to_log_severity(min_log_event),
                               event_to_log_severity(max_log_event),
                               control_event_logmsg);
}

/** Append a NUL-terminated string <b>s</b> to the end of
 * <b>conn</b>-\>outbuf
 */
static INLINE void
connection_write_str_to_buf(const char *s, control_connection_t *conn)
{
  size_t len = strlen(s);
  connection_write_to_buf(s, len, TO_CONN(conn));
}

/** Given a <b>len</b>-character string in <b>data</b>, made of lines
 * terminated by CRLF, allocate a new string in *<b>out</b>, and copy
 * the contents of <b>data</b> into *<b>out</b>, adding a period
 * before any period that that appears at the start of a line, and
 * adding a period-CRLF line at the end. If <b>translate_newlines</b>
 * is true, replace all LF characters sequences with CRLF.  Return the
 * number of bytes in *<b>out</b>.
 */
/* static */ size_t
write_escaped_data(const char *data, size_t len, int translate_newlines,
                   char **out)
{
  size_t sz_out = len+8;
  char *outp;
  const char *end;
  int i;
  int start_of_line;
  for (i=0; i<(int)len; ++i) {
    if (data[i]== '\n')
      sz_out += 2; /* Maybe add a CR; maybe add a dot. */
  }
  *out = outp = tor_malloc(sz_out+1);
  end = data+len;
  start_of_line = 1;
  while (data < end) {
    if (*data == '\n') {
      if (translate_newlines)
        *outp++ = '\r';
      start_of_line = 1;
    } else if (*data == '.') {
      if (start_of_line) {
        start_of_line = 0;
        *outp++ = '.';
      }
    } else {
      start_of_line = 0;
    }
    *outp++ = *data++;
  }
  if (outp < *out+2 || memcmp(outp-2, "\r\n", 2)) {
    *outp++ = '\r';
    *outp++ = '\n';
  }
  *outp++ = '.';
  *outp++ = '\r';
  *outp++ = '\n';
  *outp = '\0'; /* NUL-terminate just in case. */
  tor_assert((outp - *out) <= (int)sz_out);
  return outp - *out;
}

/** Given a <b>len</b>-character string in <b>data</b>, made of lines
 * terminated by CRLF, allocate a new string in *<b>out</b>, and copy
 * the contents of <b>data</b> into *<b>out</b>, removing any period
 * that appears at the start of a line.  If <b>translate_newlines</b>
 * is true, replace all CRLF sequences with LF.  Return the number of
 * bytes in *<b>out</b>. */
/*static*/ size_t
read_escaped_data(const char *data, size_t len, int translate_newlines,
                  char **out)
{
  char *outp;
  const char *next;
  const char *end;

  *out = outp = tor_malloc(len+1);

  end = data+len;

  while (data < end) {
    if (*data == '.')
      ++data;
    if (translate_newlines)
      next = tor_memmem(data, end-data, "\r\n", 2);
    else
      next = tor_memmem(data, end-data, "\r\n.", 3);
    if (next) {
      memcpy(outp, data, next-data);
      outp += (next-data);
      data = next+2;
    } else {
      memcpy(outp, data, end-data);
      outp += (end-data);
      *outp = '\0';
      return outp - *out;
    }
    if (translate_newlines) {
      *outp++ = '\n';
    } else {
      *outp++ = '\r';
      *outp++ = '\n';
    }
  }

  *outp = '\0';
  return outp - *out;
}

/** Given a pointer to a string starting at <b>start</b> containing
 * <b>in_len_max</b> characters, decode a string beginning with a single
 * quote, containing any number of non-quote characters or characters escaped
 * with a backslash, and ending with a final quote.  Place the resulting
 * string (unquoted, unescaped) into a newly allocated string in *<b>out</b>;
 * store its length in <b>out_len</b>.  On success, return a pointer to the
 * character immediately following the escaped string.  On failure, return
 * NULL. */
static const char *
get_escaped_string(const char *start, size_t in_len_max,
                   char **out, size_t *out_len)
{
  const char *cp, *end;
  char *outp;
  size_t len=0;

  if (*start != '\"')
    return NULL;

  cp = start+1;
  end = start+in_len_max;

  /* Calculate length. */
  while (1) {
    if (cp >= end)
      return NULL;
    else if (*cp == '\\') {
      if (++cp == end)
        return NULL; /* Can't escape EOS. */
      ++cp;
      ++len;
    } else if (*cp == '\"') {
      break;
    } else {
      ++cp;
      ++len;
    }
  }
  end = cp;
  outp = *out = tor_malloc(len+1);
  *out_len = len;

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

/** Acts like sprintf, but writes its formatted string to the end of
 * <b>conn</b>-\>outbuf.  The message may be truncated if it is too long,
 * but it will always end with a CRLF sequence.
 *
 * Currently the length of the message is limited to 1024 (including the
 * ending \n\r\0. */
static void
connection_printf_to_buf(control_connection_t *conn, const char *format, ...)
{
#define CONNECTION_PRINTF_TO_BUF_BUFFERSIZE 1024
  va_list ap;
  char buf[CONNECTION_PRINTF_TO_BUF_BUFFERSIZE];
  int r;
  size_t len;
  va_start(ap,format);
  r = tor_vsnprintf(buf, sizeof(buf), format, ap);
  va_end(ap);
  if (r<0) {
    log_warn(LD_BUG, "Unable to format string for controller.");
    return;
  }
  len = strlen(buf);
  if (memcmp("\r\n\0", buf+len-2, 3)) {
    buf[CONNECTION_PRINTF_TO_BUF_BUFFERSIZE-1] = '\0';
    buf[CONNECTION_PRINTF_TO_BUF_BUFFERSIZE-2] = '\n';
    buf[CONNECTION_PRINTF_TO_BUF_BUFFERSIZE-3] = '\r';
  }
  connection_write_to_buf(buf, len, TO_CONN(conn));
}

/** Send a "DONE" message down the control connection <b>conn</b> */
static void
send_control_done(control_connection_t *conn)
{
  connection_write_str_to_buf("250 OK\r\n", conn);
}

/* Send an event to all v1 controllers that are listening for code
 * <b>event</b>.  The event's body is given by <b>msg</b>.
 *
 * If <b>which</b> & SHORT_NAMES, the event contains short-format names: send
 * it to controllers that haven't enabled the VERBOSE_NAMES feature.  If
 * <b>which</b> & LONG_NAMES, the event contains long-format names: send it
 * to contollers that <em>have</em> enabled VERBOSE_NAMES.
 *
 * The EXTENDED_FORMAT and NONEXTENDED_FORMAT flags behave similarly with
 * respect to the EXTENDED_EVENTS feature. */
static void
send_control_event_string(uint16_t event, event_format_t which,
                          const char *msg)
{
  connection_t **conns;
  int n_conns, i;

  tor_assert(event >= _EVENT_MIN && event <= _EVENT_MAX);

  get_connection_array(&conns, &n_conns);
  for (i = 0; i < n_conns; ++i) {
    if (conns[i]->type == CONN_TYPE_CONTROL &&
        !conns[i]->marked_for_close &&
        conns[i]->state == CONTROL_CONN_STATE_OPEN) {
      control_connection_t *control_conn = TO_CONTROL_CONN(conns[i]);
      if (control_conn->use_long_names) {
        if (!(which & LONG_NAMES))
          continue;
      } else {
        if (!(which & SHORT_NAMES))
          continue;
      }
      if (control_conn->use_extended_events) {
        if (!(which & EXTENDED_FORMAT))
          continue;
      } else {
        if (!(which & NONEXTENDED_FORMAT))
          continue;
      }
      if (control_conn->event_mask & (1<<event)) {
        int is_err = 0;
        connection_write_to_buf(msg, strlen(msg), TO_CONN(control_conn));
        if (event == EVENT_ERR_MSG)
          is_err = 1;
        else if (event == EVENT_STATUS_GENERAL)
          is_err = !strcmpstart(msg, "STATUS_GENERAL ERR ");
        else if (event == EVENT_STATUS_CLIENT)
          is_err = !strcmpstart(msg, "STATUS_CLIENT ERR ");
        else if (event == EVENT_STATUS_SERVER)
          is_err = !strcmpstart(msg, "STATUS_SERVER ERR ");
        if (is_err)
          connection_handle_write(TO_CONN(control_conn), 1);
      }
    }
  }
}

/** Helper for send_control1_event and send_control1_event_extended:
 * Send an event to all v1 controllers that are listening for code
 * <b>event</b>.  The event's body is created by the printf-style format in
 * <b>format</b>, and other arguments as provided.
 *
 * If <b>extended</b> is true, and the format contains a single '@' character,
 * it will be replaced with a space and all text after that character will be
 * sent only to controllers that have enabled extended events.
 *
 * Currently the length of the message is limited to 1024 (including the
 * ending \n\r\0). */
static void
send_control_event_impl(uint16_t event, event_format_t which, int extended,
                         const char *format, va_list ap)
{
  /* This is just a little longer than the longest allowed log message */
#define SEND_CONTROL1_EVENT_BUFFERSIZE 10064
  int r;
  char buf[SEND_CONTROL1_EVENT_BUFFERSIZE];
  size_t len;
  char *cp;

  r = tor_vsnprintf(buf, sizeof(buf), format, ap);
  if (r<0) {
    log_warn(LD_BUG, "Unable to format event for controller.");
    return;
  }

  len = strlen(buf);
  if (memcmp("\r\n\0", buf+len-2, 3)) {
    /* if it is not properly terminated, do it now */
    buf[SEND_CONTROL1_EVENT_BUFFERSIZE-1] = '\0';
    buf[SEND_CONTROL1_EVENT_BUFFERSIZE-2] = '\n';
    buf[SEND_CONTROL1_EVENT_BUFFERSIZE-3] = '\r';
  }

  if (extended && (cp = strchr(buf, '@'))) {
    which &= ~ALL_FORMATS;
    *cp = ' ';
    send_control_event_string(event, which|EXTENDED_FORMAT, buf);
    memcpy(cp, "\r\n\0", 3);
    send_control_event_string(event, which|NONEXTENDED_FORMAT, buf);
  } else {
    send_control_event_string(event, which|ALL_FORMATS, buf);
  }
}

/* Send an event to all v1 controllers that are listening for code
 * <b>event</b>.  The event's body is created by the printf-style format in
 * <b>format</b>, and other arguments as provided.
 *
 * Currently the length of the message is limited to 1024 (including the
 * ending \n\r\0. */
static void
send_control_event(uint16_t event, event_format_t which,
                    const char *format, ...)
{
  va_list ap;
  va_start(ap, format);
  send_control_event_impl(event, which, 0, format, ap);
  va_end(ap);
}

/* Send an event to all v1 controllers that are listening for code
 * <b>event</b>.  The event's body is created by the printf-style format in
 * <b>format</b>, and other arguments as provided.
 *
 * If the format contains a single '@' character, it will be replaced with a
 * space and all text after that character will be sent only to controllers
 * that have enabled extended events.
 *
 * Currently the length of the message is limited to 1024 (including the
 * ending \n\r\0. */
static void
send_control_event_extended(uint16_t event, event_format_t which,
                             const char *format, ...)
{
  va_list ap;
  va_start(ap, format);
  send_control_event_impl(event, which, 1, format, ap);
  va_end(ap);
}

/** Given a text circuit <b>id</b>, return the corresponding circuit. */
static origin_circuit_t *
get_circ(const char *id)
{
  unsigned long n_id;
  int ok;
  n_id = tor_parse_ulong(id, 10, 0, ULONG_MAX, &ok, NULL);
  if (!ok)
    return NULL;
  return circuit_get_by_global_id(n_id);
}

/** Given a text stream <b>id</b>, return the corresponding AP connection. */
static edge_connection_t *
get_stream(const char *id)
{
  unsigned long n_id;
  int ok;
  edge_connection_t *conn;
  n_id = tor_parse_ulong(id, 10, 0, ULONG_MAX, &ok, NULL);
  if (!ok)
    return NULL;
  conn = connection_get_by_global_id(n_id);
  if (!conn || conn->_base.type != CONN_TYPE_AP)
    return NULL;
  return conn;
}

/** Helper for setconf and resetconf. Acts like setconf, except
 * it passes <b>use_defaults</b> on to options_trial_assign().  Modifies the
 * contents of body.
 */
static int
control_setconf_helper(control_connection_t *conn, uint32_t len, char *body,
                       int use_defaults)
{
  int r;
  config_line_t *lines=NULL;
  char *start = body;
  char *errstring = NULL;
  const int clear_first = 1;

  if (1) {
    char *config;
    smartlist_t *entries = smartlist_create();
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
        char *val;
        size_t val_len;
        size_t ent_len;
        if (*body != '\"') {
          char *val_start = body;
          while (!TOR_ISSPACE(*body))
            body++;
          val = tor_strndup(val_start, body-val_start);
          val_len = strlen(val);
        } else {
          body = (char*)get_escaped_string(body, (len - (body-start)),
                                           &val, &val_len);
          if (!body) {
            connection_write_str_to_buf("551 Couldn't parse string\r\n", conn);
            SMARTLIST_FOREACH(entries, char *, cp, tor_free(cp));
            smartlist_free(entries);
            return 0;
          }
        }
        ent_len = strlen(key)+val_len+3;
        entry = tor_malloc(ent_len+1);
        tor_snprintf(entry, ent_len, "%s %s", key, val);
        tor_free(key);
        tor_free(val);
      } else {
        entry = key;
      }
      smartlist_add(entries, entry);
      while (TOR_ISSPACE(*body))
        ++body;
    }

    smartlist_add(entries, tor_strdup(""));
    config = smartlist_join_strings(entries, "\n", 0, NULL);
    SMARTLIST_FOREACH(entries, char *, cp, tor_free(cp));
    smartlist_free(entries);

    if (config_get_lines(config, &lines) < 0) {
      log_warn(LD_CONTROL,"Controller gave us config lines we can't parse.");
      connection_write_str_to_buf("551 Couldn't parse configuration\r\n",
                                  conn);
      tor_free(config);
      return 0;
    }
    tor_free(config);
  }

  if ((r=options_trial_assign(lines, use_defaults,
                              clear_first, &errstring)) < 0) {
    const char *msg;
    log_warn(LD_CONTROL,
             "Controller gave us config lines that didn't validate: %s.",
             errstring);
    switch (r) {
      case -1:
        msg = "552 Unrecognized option";
        break;
      case -2:
        msg = "513 Unacceptable option value";
        break;
      case -3:
        msg = "553 Transition not allowed";
        break;
      case -4:
      default:
        msg = "553 Unable to set option";
        break;
    }
    connection_printf_to_buf(conn, "%s: %s\r\n", msg, errstring);
    config_free_lines(lines);
    tor_free(errstring);
    return 0;
  }
  config_free_lines(lines);
  send_control_done(conn);
  return 0;
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
  smartlist_t *questions = NULL;
  smartlist_t *answers = NULL;
  smartlist_t *unrecognized = NULL;
  char *msg = NULL;
  size_t msg_len;
  or_options_t *options = get_options();

  questions = smartlist_create();
  (void) body_len; /* body is nul-terminated; so we can ignore len. */
  smartlist_split_string(questions, body, " ",
                         SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 0);
  answers = smartlist_create();
  unrecognized = smartlist_create();
  SMARTLIST_FOREACH(questions, char *, q,
  {
    if (!option_is_recognized(q)) {
      smartlist_add(unrecognized, q);
    } else {
      config_line_t *answer = option_get_assignment(options,q);
      if (!answer) {
        const char *name = option_get_canonical_name(q);
        size_t alen = strlen(name)+8;
        char *astr = tor_malloc(alen);
        tor_snprintf(astr, alen, "250-%s\r\n", name);
        smartlist_add(answers, astr);
      }

      while (answer) {
        config_line_t *next;
        size_t alen = strlen(answer->key)+strlen(answer->value)+8;
        char *astr = tor_malloc(alen);
        tor_snprintf(astr, alen, "250-%s=%s\r\n",
                     answer->key, answer->value);
        smartlist_add(answers, astr);

        next = answer->next;
        tor_free(answer->key);
        tor_free(answer->value);
        tor_free(answer);
        answer = next;
      }
    }
  });

  if (1) {
    int i,len;
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
      connection_write_to_buf(msg, msg_len, TO_CONN(conn));
    } else {
      connection_write_str_to_buf("250 OK\r\n", conn);
    }
  }

  if (answers) {
    SMARTLIST_FOREACH(answers, char *, cp, tor_free(cp));
    smartlist_free(answers);
  }
  if (questions) {
    SMARTLIST_FOREACH(questions, char *, cp, tor_free(cp));
    smartlist_free(questions);
  }
  smartlist_free(unrecognized);
  tor_free(msg);

  return 0;
}

/** Called when we get a SETEVENTS message: update conn->event_mask,
 * and reply with DONE or ERROR. */
static int
handle_control_setevents(control_connection_t *conn, uint32_t len,
                         const char *body)
{
  uint16_t event_code;
  uint32_t event_mask = 0;
  unsigned int extended = 0;
  (void) len;

  if (1) {
    smartlist_t *events = smartlist_create();
    smartlist_split_string(events, body, " ",
                           SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 0);
    SMARTLIST_FOREACH(events, const char *, ev,
      {
        if (!strcasecmp(ev, "EXTENDED")) {
          extended = 1;
          continue;
        } else if (!strcasecmp(ev, "CIRC"))
          event_code = EVENT_CIRCUIT_STATUS;
        else if (!strcasecmp(ev, "STREAM"))
          event_code = EVENT_STREAM_STATUS;
        else if (!strcasecmp(ev, "ORCONN"))
          event_code = EVENT_OR_CONN_STATUS;
        else if (!strcasecmp(ev, "BW"))
          event_code = EVENT_BANDWIDTH_USED;
        else if (!strcasecmp(ev, "DEBUG"))
          event_code = EVENT_DEBUG_MSG;
        else if (!strcasecmp(ev, "INFO"))
          event_code = EVENT_INFO_MSG;
        else if (!strcasecmp(ev, "NOTICE"))
          event_code = EVENT_NOTICE_MSG;
        else if (!strcasecmp(ev, "WARN"))
          event_code = EVENT_WARN_MSG;
        else if (!strcasecmp(ev, "ERR"))
          event_code = EVENT_ERR_MSG;
        else if (!strcasecmp(ev, "NEWDESC"))
          event_code = EVENT_NEW_DESC;
        else if (!strcasecmp(ev, "ADDRMAP"))
          event_code = EVENT_ADDRMAP;
        else if (!strcasecmp(ev, "AUTHDIR_NEWDESCS"))
          event_code = EVENT_AUTHDIR_NEWDESCS;
        else if (!strcasecmp(ev, "DESCCHANGED"))
          event_code = EVENT_DESCCHANGED;
        else if (!strcasecmp(ev, "NS"))
          event_code = EVENT_NS;
        else if (!strcasecmp(ev, "STATUS_GENERAL"))
          event_code = EVENT_STATUS_GENERAL;
        else if (!strcasecmp(ev, "STATUS_CLIENT"))
          event_code = EVENT_STATUS_CLIENT;
        else if (!strcasecmp(ev, "STATUS_SERVER"))
          event_code = EVENT_STATUS_SERVER;
        else if (!strcasecmp(ev, "GUARD"))
          event_code = EVENT_GUARD;
        else if (!strcasecmp(ev, "GUARDS")) {
          /* XXX tolerate buggy spec in 0.1.2.5-alpha through 0.1.2.10-rc */
          event_code = EVENT_GUARD;
        } else if (!strcasecmp(ev, "STREAM_BW"))
          event_code = EVENT_STREAM_BANDWIDTH_USED;
        else {
          connection_printf_to_buf(conn, "552 Unrecognized event \"%s\"\r\n",
                                   ev);
          SMARTLIST_FOREACH(events, char *, e, tor_free(e));
          smartlist_free(events);
          return 0;
        }
        event_mask |= (1 << event_code);
      });
    SMARTLIST_FOREACH(events, char *, e, tor_free(e));
    smartlist_free(events);
  }
  conn->event_mask = event_mask;
  if (extended)
    conn->use_extended_events = 1;

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
handle_control_authenticate(control_connection_t *conn, uint32_t len,
                            const char *body)
{
  int used_quoted_string = 0;
  or_options_t *options = get_options();
  const char *errstr = NULL;
  char *password;
  size_t password_len;
  if (1) {
    if (TOR_ISXDIGIT(body[0])) {
      int i = 0;
      while (TOR_ISXDIGIT(body[i]))
        ++i;
      password = tor_malloc(i/2 + 1);
      if (base16_decode(password, i/2+1, body, i)<0) {
        connection_write_str_to_buf(
            "551 Invalid hexadecimal encoding.  Maybe you tried a plain text "
            "password?  If so, the standard requires that you put it in "
            "double quotes.\r\n", conn);
        tor_free(password);
        return 0;
      }
      password_len = i/2;
    } else if (TOR_ISSPACE(body[0])) {
      password = tor_strdup("");
      password_len = 0;
    } else {
      if (!get_escaped_string(body, len, &password, &password_len)) {
        connection_write_str_to_buf("551 Invalid quoted string.  You need "
            "to put the password in double quotes.\r\n", conn);
        return 0;
      }
      used_quoted_string = 1;
    }
  }
  if (options->CookieAuthentication && authentication_cookie_is_set) {
    if (password_len != AUTHENTICATION_COOKIE_LEN) {
      log_warn(LD_CONTROL, "Got authentication cookie with wrong length (%d)",
               (int)password_len);
      errstr = "Wrong length on authentication cookie.";
      goto err;
    } else if (memcmp(authentication_cookie, password, password_len)) {
      log_warn(LD_CONTROL, "Got mismatched authentication cookie");
      errstr = "Authentication cookie did not match expected value.";
      goto err;
    } else {
      goto ok;
    }
  } else if (options->HashedControlPassword) {
    char expected[S2K_SPECIFIER_LEN+DIGEST_LEN];
    char received[DIGEST_LEN];
    if (decode_hashed_password(expected, options->HashedControlPassword)<0) {
      log_warn(LD_CONTROL,
               "Couldn't decode HashedControlPassword: invalid base16");
      errstr = "Couldn't decode HashedControlPassword value in configuration.";
      goto err;
    }
    secret_to_key(received,DIGEST_LEN,password,password_len,expected);
    if (!memcmp(expected+S2K_SPECIFIER_LEN, received, DIGEST_LEN))
      goto ok;

    if (used_quoted_string)
      errstr = "Password did not match HashedControlPassword value from "
        "configuration";
    else
      errstr = "Password did not match HashedControlPassword value from "
        "configuration. Maybe you tried a plain text password? "
        "If so, the standard requires that you put it in double quotes.";
    goto err;
  } else {
    /* if Tor doesn't demand any stronger authentication, then
     * the controller can get in with anything. */
    goto ok;
  }

 err:
  tor_free(password);
  if (!errstr)
    errstr = "Unknown reason.";
  connection_printf_to_buf(conn, "515 Authentication failed: %s\r\n",
                           errstr);
  return 0;
 ok:
  log_info(LD_CONTROL, "Authenticated control connection (%d)", conn->_base.s);
  send_control_done(conn);
  conn->_base.state = CONTROL_CONN_STATE_OPEN;
  tor_free(password);
  return 0;
}

/** Called when we get a SAVECONF command. Try to flush the current options to
 * disk, and report success or failure. */
static int
handle_control_saveconf(control_connection_t *conn, uint32_t len,
                        const char *body)
{
  (void) len;
  (void) body;
  if (options_save_current()<0) {
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
  int sig;
  (void) len;

  if (1) {
    int n = 0;
    char *s;
    while (body[n] && ! TOR_ISSPACE(body[n]))
      ++n;
    s = tor_strndup(body, n);
    if (!strcasecmp(s, "RELOAD") || !strcasecmp(s, "HUP"))
      sig = SIGHUP;
    else if (!strcasecmp(s, "SHUTDOWN") || !strcasecmp(s, "INT"))
      sig = SIGINT;
    else if (!strcasecmp(s, "DUMP") || !strcasecmp(s, "USR1"))
      sig = SIGUSR1;
    else if (!strcasecmp(s, "DEBUG") || !strcasecmp(s, "USR2"))
      sig = SIGUSR2;
    else if (!strcasecmp(s, "HALT") || !strcasecmp(s, "TERM"))
      sig = SIGTERM;
    else if (!strcasecmp(s, "NEWNYM"))
      sig = SIGNEWNYM;
    else if (!strcasecmp(s, "CLEARDNSCACHE"))
      sig = SIGCLEARDNSCACHE;
    else {
      connection_printf_to_buf(conn, "552 Unrecognized signal code \"%s\"\r\n",
                               s);
      sig = -1;
    }
    tor_free(s);
    if (sig<0)
      return 0;
  }

  /* Send DONE first, in case the signal makes us shut down. */
  send_control_done(conn);
  control_signal_act(sig);
  return 0;
}

/** Called when we get a MAPADDRESS command; try to bind all listed addresses,
 * and report success or failrue. */
static int
handle_control_mapaddress(control_connection_t *conn, uint32_t len,
                          const char *body)
{
  smartlist_t *elts;
  smartlist_t *lines;
  smartlist_t *reply;
  char *r;
  size_t sz;
  (void) len; /* body is nul-terminated, so it's safe to ignore the length. */

  lines = smartlist_create();
  elts = smartlist_create();
  reply = smartlist_create();
  smartlist_split_string(lines, body, " ",
                         SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 0);
  SMARTLIST_FOREACH(lines, char *, line,
  {
    tor_strlower(line);
    smartlist_split_string(elts, line, "=", 0, 2);
    if (smartlist_len(elts) == 2) {
      const char *from = smartlist_get(elts,0);
      const char *to = smartlist_get(elts,1);
      size_t anslen = strlen(line)+512;
      char *ans = tor_malloc(anslen);
      if (address_is_invalid_destination(to, 1)) {
        tor_snprintf(ans, anslen,
                     "512-syntax error: invalid address '%s'", to);
        smartlist_add(reply, ans);
        log_warn(LD_CONTROL,
                 "Skipping invalid argument '%s' in MapAddress msg", to);
      } else if (!strcmp(from, ".") || !strcmp(from, "0.0.0.0")) {
        const char *address = addressmap_register_virtual_address(
              !strcmp(from,".") ? RESOLVED_TYPE_HOSTNAME : RESOLVED_TYPE_IPV4,
               tor_strdup(to));
        if (!address) {
          tor_snprintf(ans, anslen,
                       "451-resource exhausted: skipping '%s'", line);
          smartlist_add(reply, ans);
          log_warn(LD_CONTROL,
                   "Unable to allocate address for '%s' in MapAddress msg",
                   safe_str(line));
        } else {
          tor_snprintf(ans, anslen, "250-%s=%s", address, to);
          smartlist_add(reply, ans);
        }
      } else {
        addressmap_register(from, tor_strdup(to), 1);
        tor_snprintf(ans, anslen, "250-%s", line);
        smartlist_add(reply, ans);
      }
    } else {
      size_t anslen = strlen(line)+256;
      char *ans = tor_malloc(anslen);
      tor_snprintf(ans, anslen, "512-syntax error: mapping '%s' is "
                   "not of expected form 'foo=bar'.", line);
      smartlist_add(reply, ans);
      log_info(LD_CONTROL, "Skipping MapAddress '%s': wrong "
                           "number of items.", safe_str(line));
    }
    SMARTLIST_FOREACH(elts, char *, cp, tor_free(cp));
    smartlist_clear(elts);
  });
  SMARTLIST_FOREACH(lines, char *, cp, tor_free(cp));
  smartlist_free(lines);
  smartlist_free(elts);

  if (1) {
    if (smartlist_len(reply)) {
      ((char*)smartlist_get(reply,smartlist_len(reply)-1))[3] = ' ';
      r = smartlist_join_strings(reply, "\r\n", 1, &sz);
      connection_write_to_buf(r, sz, TO_CONN(conn));
      tor_free(r);
    } else {
      const char *response =
        "512 syntax error: not enough arguments to mapaddress.\r\n";
      connection_write_to_buf(response, strlen(response), TO_CONN(conn));
    }
  }

  SMARTLIST_FOREACH(reply, char *, cp, tor_free(cp));
  smartlist_free(reply);
  return 0;
}

/** Implementation helper for GETINFO: knows the answers for various
 * trivial-to-implement questions. */
static int
getinfo_helper_misc(control_connection_t *conn, const char *question,
                    char **answer)
{
  (void) conn;
  if (!strcmp(question, "version")) {
    *answer = tor_strdup(VERSION);
  } else if (!strcmp(question, "config-file")) {
    *answer = tor_strdup(get_torrc_fname());
  } else if (!strcmp(question, "info/names")) {
    *answer = list_getinfo_options();
  } else if (!strcmp(question, "events/names")) {
    *answer = tor_strdup("CIRC STREAM ORCONN BW DEBUG INFO NOTICE WARN ERR "
                         "NEWDESC ADDRMAP AUTHDIR_NEWDESCS DESCCHANGED "
                         "NS STATUS_GENERAL STATUS_CLIENT STATUS_SERVER "
                         "GUARD STREAM_BW");
  } else if (!strcmp(question, "features/names")) {
    *answer = tor_strdup("VERBOSE_NAMES EXTENDED_EVENTS");
  } else if (!strcmp(question, "address")) {
    uint32_t addr;
    if (router_pick_published_address(get_options(), &addr) < 0)
      return -1;
    *answer = tor_dup_addr(addr);
  } else if (!strcmp(question, "dir-usage")) {
    *answer = directory_dump_request_log();
  } else if (!strcmp(question, "fingerprint")) {
    routerinfo_t *me = router_get_my_routerinfo();
    if (!me)
      return -1;
    *answer = tor_malloc(HEX_DIGEST_LEN+1);
    base16_encode(*answer, HEX_DIGEST_LEN+1, me->cache_info.identity_digest,
                  DIGEST_LEN);
  }
  return 0;
}

/** Implementation helper for GETINFO: knows the answers for questions about
 * directory information. */
static int
getinfo_helper_dir(control_connection_t *control_conn,
                   const char *question, char **answer)
{
  if (!strcmpstart(question, "desc/id/")) {
    routerinfo_t *ri = router_get_by_hexdigest(question+strlen("desc/id/"));
    if (ri) {
      const char *body = signed_descriptor_get_body(&ri->cache_info);
      if (body)
        *answer = tor_strndup(body, ri->cache_info.signed_descriptor_len);
    }
  } else if (!strcmpstart(question, "desc/name/")) {
    routerinfo_t *ri = router_get_by_nickname(question+strlen("desc/name/"),1);
    if (ri) {
      const char *body = signed_descriptor_get_body(&ri->cache_info);
      if (body)
        *answer = tor_strndup(body, ri->cache_info.signed_descriptor_len);
    }
  } else if (!strcmp(question, "desc/all-recent")) {
    routerlist_t *routerlist = router_get_routerlist();
    smartlist_t *sl = smartlist_create();
    if (routerlist && routerlist->routers) {
      SMARTLIST_FOREACH(routerlist->routers, routerinfo_t *, ri,
      {
        const char *body = signed_descriptor_get_body(&ri->cache_info);
        if (body)
          smartlist_add(sl,
                  tor_strndup(body, ri->cache_info.signed_descriptor_len));
      });
    }
    *answer = smartlist_join_strings(sl, "", 0, NULL);
    SMARTLIST_FOREACH(sl, char *, c, tor_free(c));
    smartlist_free(sl);
  } else if (!strcmpstart(question, "dir/server/")) {
    size_t answer_len = 0, url_len = strlen(question)+2;
    char *url = tor_malloc(url_len);
    smartlist_t *descs = smartlist_create();
    const char *msg;
    int res;
    char *cp;
    tor_snprintf(url, url_len, "/tor/%s", question+4);
    res = dirserv_get_routerdescs(descs, url, &msg);
    if (res) {
      log_warn(LD_CONTROL, "getinfo '%s': %s", question, msg);
      return -1;
    }
    SMARTLIST_FOREACH(descs, signed_descriptor_t *, sd,
                      answer_len += sd->signed_descriptor_len);
    cp = *answer = tor_malloc(answer_len+1);
    SMARTLIST_FOREACH(descs, signed_descriptor_t *, sd,
                      {
                        memcpy(cp, signed_descriptor_get_body(sd),
                               sd->signed_descriptor_len);
                        cp += sd->signed_descriptor_len;
                      });
    *cp = '\0';
    tor_free(url);
    smartlist_free(descs);
  } else if (!strcmpstart(question, "dir/status/")) {
    if (get_options()->DirPort) {
      size_t len=0;
      char *cp;
      smartlist_t *status_list = smartlist_create();
      dirserv_get_networkstatus_v2(status_list,
                                   question+strlen("dir/status/"));
      SMARTLIST_FOREACH(status_list, cached_dir_t *, d, len += d->dir_len);
      cp = *answer = tor_malloc(len+1);
      SMARTLIST_FOREACH(status_list, cached_dir_t *, d, {
          memcpy(cp, d->dir, d->dir_len);
          cp += d->dir_len;
        });
      *cp = '\0';
      smartlist_free(status_list);
    } else {
      smartlist_t *fp_list = smartlist_create();
      smartlist_t *status_list = smartlist_create();
      size_t fn_len = strlen(get_options()->DataDirectory)+HEX_DIGEST_LEN+32;
      char *fn = tor_malloc(fn_len+1);
      char hex_id[HEX_DIGEST_LEN+1];
      dirserv_get_networkstatus_v2_fingerprints(
                             fp_list, question+strlen("dir/status/"));
      SMARTLIST_FOREACH(fp_list, const char *, fp, {
          char *s;
          base16_encode(hex_id, sizeof(hex_id), fp, DIGEST_LEN);
          tor_snprintf(fn, fn_len, "%s/cached-status/%s",
                       get_options()->DataDirectory, hex_id);
          s = read_file_to_str(fn, 0, NULL);
          if (s)
            smartlist_add(status_list, s);
        });
      SMARTLIST_FOREACH(fp_list, char *, fp, tor_free(fp));
      smartlist_free(fp_list);
      *answer = smartlist_join_strings(status_list, "", 0, NULL);
      SMARTLIST_FOREACH(status_list, char *, s, tor_free(s));
      smartlist_free(status_list);
    }
  } else if (!strcmp(question, "network-status")) {
    routerlist_t *routerlist = router_get_routerlist();
    int verbose = control_conn->use_long_names;
    if (!routerlist || !routerlist->routers ||
        list_server_status(routerlist->routers, answer, verbose ? 2 : 1) < 0) {
      return -1;
    }
  }
  return 0;
}

/** Implementation helper for GETINFO: knows how to generate summaries of the
 * current states of things we send events about. */
static int
getinfo_helper_events(control_connection_t *control_conn,
                      const char *question, char **answer)
{
  if (!strcmp(question, "circuit-status")) {
    circuit_t *circ;
    smartlist_t *status = smartlist_create();
    for (circ = _circuit_get_global_list(); circ; circ = circ->next) {
      char *s, *path;
      size_t slen;
      const char *state;
      if (! CIRCUIT_IS_ORIGIN(circ) || circ->marked_for_close)
        continue;
      if (control_conn->use_long_names)
        path = circuit_list_path_for_controller(TO_ORIGIN_CIRCUIT(circ));
      else
        path = circuit_list_path(TO_ORIGIN_CIRCUIT(circ),0);
      if (circ->state == CIRCUIT_STATE_OPEN)
        state = "BUILT";
      else if (strlen(path))
        state = "EXTENDED";
      else
        state = "LAUNCHED";

      slen = strlen(path)+strlen(state)+20;
      s = tor_malloc(slen+1);
      tor_snprintf(s, slen, "%lu %s %s",
                   (unsigned long)TO_ORIGIN_CIRCUIT(circ)->global_identifier,
                   state, path);
      smartlist_add(status, s);
      tor_free(path);
    }
    *answer = smartlist_join_strings(status, "\r\n", 0, NULL);
    SMARTLIST_FOREACH(status, char *, cp, tor_free(cp));
    smartlist_free(status);
  } else if (!strcmp(question, "stream-status")) {
    connection_t **conns;
    int n_conns, i;
    char buf[256];
    smartlist_t *status = smartlist_create();
    get_connection_array(&conns, &n_conns);
    for (i=0; i < n_conns; ++i) {
      const char *state;
      edge_connection_t *conn;
      char *s;
      size_t slen;
      circuit_t *circ;
      origin_circuit_t *origin_circ = NULL;
      if (conns[i]->type != CONN_TYPE_AP ||
          conns[i]->marked_for_close ||
          conns[i]->state == AP_CONN_STATE_SOCKS_WAIT ||
          conns[i]->state == AP_CONN_STATE_NATD_WAIT)
        continue;
      conn = TO_EDGE_CONN(conns[i]);
      switch (conn->_base.state)
        {
        case AP_CONN_STATE_CONTROLLER_WAIT:
        case AP_CONN_STATE_CIRCUIT_WAIT:
          if (conn->socks_request &&
              SOCKS_COMMAND_IS_RESOLVE(conn->socks_request->command))
            state = "NEWRESOLVE";
          else
            state = "NEW";
          break;
        case AP_CONN_STATE_RENDDESC_WAIT:
        case AP_CONN_STATE_CONNECT_WAIT:
          state = "SENTCONNECT"; break;
        case AP_CONN_STATE_RESOLVE_WAIT:
          state = "SENTRESOLVE"; break;
        case AP_CONN_STATE_OPEN:
          state = "SUCCEEDED"; break;
        default:
          log_warn(LD_BUG, "Asked for stream in unknown state %d",
                   conn->_base.state);
          continue;
        }
      circ = circuit_get_by_edge_conn(conn);
      if (circ && CIRCUIT_IS_ORIGIN(circ))
        origin_circ = TO_ORIGIN_CIRCUIT(circ);
      write_stream_target_to_buf(conn, buf, sizeof(buf));
      slen = strlen(buf)+strlen(state)+32;
      s = tor_malloc(slen+1);
      tor_snprintf(s, slen, "%lu %s %lu %s",
                   (unsigned long) conn->global_identifier,state,
                   origin_circ?
                         (unsigned long)origin_circ->global_identifier : 0ul,
                   buf);
      smartlist_add(status, s);
    }
    *answer = smartlist_join_strings(status, "\r\n", 0, NULL);
    SMARTLIST_FOREACH(status, char *, cp, tor_free(cp));
    smartlist_free(status);
  } else if (!strcmp(question, "orconn-status")) {
    connection_t **conns;
    int n_conns, i;
    smartlist_t *status = smartlist_create();
    get_connection_array(&conns, &n_conns);
    for (i=0; i < n_conns; ++i) {
      const char *state;
      char *s;
      char name[128];
      size_t slen;
      or_connection_t *conn;
      if (conns[i]->type != CONN_TYPE_OR || conns[i]->marked_for_close)
        continue;
      conn = TO_OR_CONN(conns[i]);
      if (conn->_base.state == OR_CONN_STATE_OPEN)
        state = "CONNECTED";
      else if (conn->nickname)
        state = "LAUNCHED";
      else
        state = "NEW";
      orconn_target_get_name(control_conn->use_long_names, name, sizeof(name),
                             conn);
      slen = strlen(name)+strlen(state)+2;
      s = tor_malloc(slen+1);
      tor_snprintf(s, slen, "%s %s", name, state);
      smartlist_add(status, s);
    }
    *answer = smartlist_join_strings(status, "\r\n", 0, NULL);
    SMARTLIST_FOREACH(status, char *, cp, tor_free(cp));
    smartlist_free(status);
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
    *answer = smartlist_join_strings(mappings, "\r\n", 0, NULL);
    SMARTLIST_FOREACH(mappings, char *, cp, tor_free(cp));
    smartlist_free(mappings);
  }
  return 0;
}

/** Callback function for GETINFO: on a given control connection, try to
 * answer the question <b>q</b> and store the newly-allocated answer in
 * *<b>a</b>.  If there's no answer, or an error occurs, just don't set
 * <b>a</b>.  Return 0.
 */
typedef int (*getinfo_helper_t)(control_connection_t *,
                                const char *q, char **a);

/** A single item for the GETINFO question-to-answer-function table. */
typedef struct getinfo_item_t {
  const char *varname; /**< The value (or prefix) of the question. */
  getinfo_helper_t fn; /**< The function that knows the answer: NULL if
                        * this entry is documentation-only. */
  const char *desc; /**< Description of the variable. */
  int is_prefix; /** Must varname match exactly, or must it be a prefix? */
} getinfo_item_t;

#define ITEM(name, fn, desc) { name, getinfo_helper_##fn, desc, 0 }
#define PREFIX(name, fn, desc) { name, getinfo_helper_##fn, desc, 1 }
#define DOC(name, desc) { name, NULL, desc, 0 }

/** Table mapping questions accepted by GETINFO to the functions that know how
 * to answer them. */
static const getinfo_item_t getinfo_items[] = {
  ITEM("version", misc, "The current version of Tor."),
  ITEM("config-file", misc, "Current location of the \"torrc\" file."),
  ITEM("accounting/bytes", accounting,
       "Number of bytes read/written so far in the accounting interval."),
  ITEM("accounting/bytes-left", accounting,
      "Number of bytes left to write/read so far in the accounting interval."),
  ITEM("accounting/enabled", accounting, "Is accounting currently enabled?"),
  ITEM("accounting/hibernating", accounting, "Are we hibernating or awake?"),
  ITEM("accounting/interval-start", accounting,
       "Time when the accounting period starts."),
  ITEM("accounting/interval-end", accounting,
       "Time when the accounting period ends."),
  ITEM("accounting/interval-wake", accounting,
       "Time to wake up in this accounting period."),
  ITEM("helper-nodes", entry_guards, NULL), /* deprecated */
  ITEM("entry-guards", entry_guards,
       "Which nodes are we using as entry guards?"),
  ITEM("fingerprint", misc, NULL),
  PREFIX("config/", config, "Current configuration values."),
  DOC("config/names",
      "List of configuration options, types, and documentation."),
  ITEM("info/names", misc,
       "List of GETINFO options, types, and documentation."),
  ITEM("events/names", misc,
       "Events that the controller can ask for with SETEVENTS."),
  ITEM("features/names", misc, "What arguments can USEFEATURE take?"),
  PREFIX("desc/id/", dir, "Router descriptors by ID."),
  PREFIX("desc/name/", dir, "Router descriptors by nickname."),
  ITEM("desc/all-recent", dir,
       "All non-expired, non-superseded router descriptors."),
  ITEM("ns/all", networkstatus,
       "Brief summary of router status (v2 directory format)"),
  PREFIX("ns/id/", networkstatus,
         "Brief summary of router status by ID (v2 directory format)."),
  PREFIX("ns/name/", networkstatus,
         "Brief summary of router status by nickname (v2 directory format)."),

  PREFIX("unregisterd-servers-", dirserv_unregistered, NULL),
  ITEM("network-status", dir,
       "Brief summary of router status (v1 directory format)"),
  ITEM("circuit-status", events, "List of current circuits originating here."),
  ITEM("stream-status", events,"List of current streams."),
  ITEM("orconn-status", events, "A list of current OR connections."),
  PREFIX("addr-mappings/", events, NULL),
  DOC("addr-mappings/all", "Current address mappings."),
  DOC("addr-mappings/cache", "Current cached DNS replies."),
  DOC("addr-mappings/config", "Current address mappings from configuration."),
  DOC("addr-mappings/control", "Current address mappings from controller."),

  ITEM("address", misc, "IP address of this Tor host, if we can guess it."),
  ITEM("dir-usage", misc, "Breakdown of bytes transferred over DirPort."),
  PREFIX("dir/server/", dir,"Router descriptors as retrieved from a DirPort."),
  PREFIX("dir/status/", dir,"Networkstatus docs as retrieved from a DirPort."),
  PREFIX("exit-policy/default", policies,
         "The default value appended to the configured exit policy."),

  { NULL, NULL, NULL, 0 }
};

/** Allocate and return a list of recognized GETINFO options. */
static char *
list_getinfo_options(void)
{
  int i;
  char buf[300];
  smartlist_t *lines = smartlist_create();
  char *ans;
  for (i = 0; getinfo_items[i].varname; ++i) {
    if (!getinfo_items[i].desc)
      continue;

    tor_snprintf(buf, sizeof(buf), "%s%s -- %s\n",
                 getinfo_items[i].varname,
                 getinfo_items[i].is_prefix ? "*" : "",
                 getinfo_items[i].desc);
    smartlist_add(lines, tor_strdup(buf));
  }
  smartlist_sort_strings(lines);

  ans = smartlist_join_strings(lines, "", 0, NULL);
  SMARTLIST_FOREACH(lines, char *, cp, tor_free(cp));
  smartlist_free(lines);

  return ans;
}

/** Lookup the 'getinfo' entry <b>question</b>, and return
 * the answer in <b>*answer</b> (or NULL if key not recognized).
 * Return 0 if success or unrecognized, or -1 if recognized but
 * internal error. */
static int
handle_getinfo_helper(control_connection_t *control_conn,
                      const char *question, char **answer)
{
  int i;
  *answer = NULL; /* unrecognized key by default */

  for (i = 0; getinfo_items[i].varname; ++i) {
    int match;
    if (getinfo_items[i].is_prefix)
      match = !strcmpstart(question, getinfo_items[i].varname);
    else
      match = !strcmp(question, getinfo_items[i].varname);
    if (match) {
      tor_assert(getinfo_items[i].fn);
      return getinfo_items[i].fn(control_conn, question, answer);
    }
  }

  return 0; /* unrecognized */
}

/** Called when we receive a GETINFO command.  Try to fetch all requested
 * information, and reply with information or error message. */
static int
handle_control_getinfo(control_connection_t *conn, uint32_t len,
                       const char *body)
{
  smartlist_t *questions = NULL;
  smartlist_t *answers = NULL;
  smartlist_t *unrecognized = NULL;
  char *msg = NULL, *ans = NULL;
  (void) len; /* body is nul-terminated, so it's safe to ignore the length. */

  questions = smartlist_create();
  smartlist_split_string(questions, body, " ",
                         SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 0);
  answers = smartlist_create();
  unrecognized = smartlist_create();
  SMARTLIST_FOREACH(questions, const char *, q,
  {
    if (handle_getinfo_helper(conn, q, &ans) < 0) {
      connection_write_str_to_buf("551 Internal error\r\n", conn);
      goto done;
    }
    if (!ans) {
      smartlist_add(unrecognized, (char*)q);
    } else {
      smartlist_add(answers, tor_strdup(q));
      smartlist_add(answers, ans);
    }
  });
  if (smartlist_len(unrecognized)) {
    int i;
    for (i=0; i < smartlist_len(unrecognized)-1; ++i)
      connection_printf_to_buf(conn,
                               "552-Unrecognized key \"%s\"\r\n",
                               (char*)smartlist_get(unrecognized, i));
    connection_printf_to_buf(conn,
                             "552 Unrecognized key \"%s\"\r\n",
                             (char*)smartlist_get(unrecognized, i));
    goto done;
  }

  if (1) {
    int i;
    for (i = 0; i < smartlist_len(answers); i += 2) {
      char *k = smartlist_get(answers, i);
      char *v = smartlist_get(answers, i+1);
      if (!strchr(v, '\n') && !strchr(v, '\r')) {
        connection_printf_to_buf(conn, "250-%s=", k);
        connection_write_str_to_buf(v, conn);
        connection_write_str_to_buf("\r\n", conn);
      } else {
        char *esc = NULL;
        size_t len;
        len = write_escaped_data(v, strlen(v), 1, &esc);
        connection_printf_to_buf(conn, "250+%s=\r\n", k);
        connection_write_to_buf(esc, len, TO_CONN(conn));
        tor_free(esc);
      }
    }
    connection_write_str_to_buf("250 OK\r\n", conn);
  }

 done:
  if (answers) {
    SMARTLIST_FOREACH(answers, char *, cp, tor_free(cp));
    smartlist_free(answers);
  }
  if (questions) {
    SMARTLIST_FOREACH(questions, char *, cp, tor_free(cp));
    smartlist_free(questions);
  }
  smartlist_free(unrecognized);
  tor_free(msg);

  return 0;
}

/** If *<b>string</b> contains a recognized purpose (for
 * circuits if <b>for_circuits</b> is 1, else for routers),
 * possibly prefaced with the string "purpose=", then assign it
 * and return 0. Otherwise return -1.
 *
 * If it's prefaced with "purpose=", then set *<b>string</b> to
 * the remainder of the string. */
static int
get_purpose(char **string, int for_circuits, uint8_t *purpose)
{
  if (!strcmpstart(*string, "purpose="))
    *string += strlen("purpose=");

  if (!strcmp(*string, "general"))
    *purpose = for_circuits ? CIRCUIT_PURPOSE_C_GENERAL :
                              ROUTER_PURPOSE_GENERAL;
  else if (!strcmp(*string, "controller"))
    *purpose = for_circuits ? CIRCUIT_PURPOSE_CONTROLLER :
                              ROUTER_PURPOSE_GENERAL;
  else { /* not a recognized purpose */
    return -1;
  }
  return 0;
}

/** Called when we get an EXTENDCIRCUIT message.  Try to extend the listed
 * circuit, and report success or failure. */
static int
handle_control_extendcircuit(control_connection_t *conn, uint32_t len,
                             const char *body)
{
  smartlist_t *router_nicknames=NULL, *routers=NULL;
  origin_circuit_t *circ = NULL;
  int zero_circ;
  uint8_t intended_purpose = CIRCUIT_PURPOSE_C_GENERAL;
  (void) len;

  router_nicknames = smartlist_create();

  if (1) {
    smartlist_t *args;
    args = smartlist_create();
    smartlist_split_string(args, body, " ",
                           SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 0);
    if (smartlist_len(args)<2) {
      connection_printf_to_buf(conn,
                               "512 Missing argument to EXTENDCIRCUIT\r\n");
      SMARTLIST_FOREACH(args, char *, cp, tor_free(cp));
      smartlist_free(args);
      goto done;
    }

    zero_circ = !strcmp("0", (char*)smartlist_get(args,0));
    if (!zero_circ && !(circ = get_circ(smartlist_get(args,0)))) {
      connection_printf_to_buf(conn, "552 Unknown circuit \"%s\"\r\n",
                               (char*)smartlist_get(args, 0));
    }
    smartlist_split_string(router_nicknames, smartlist_get(args,1), ",", 0, 0);

    if (zero_circ && smartlist_len(args)>2) {
      char *purp = smartlist_get(args,2);
      if (get_purpose(&purp, 1, &intended_purpose) < 0) {
        connection_printf_to_buf(conn, "552 Unknown purpose \"%s\"\r\n", purp);
        SMARTLIST_FOREACH(args, char *, cp, tor_free(cp));
        smartlist_free(args);
        goto done;
      }
    }
    SMARTLIST_FOREACH(args, char *, cp, tor_free(cp));
    smartlist_free(args);
    if (!zero_circ && !circ) {
      goto done;
    }
  }

  routers = smartlist_create();
  SMARTLIST_FOREACH(router_nicknames, const char *, n,
  {
    routerinfo_t *r = router_get_by_nickname(n, 1);
    if (!r) {
      connection_printf_to_buf(conn, "552 No such router \"%s\"\r\n", n);
      goto done;
    }
    smartlist_add(routers, r);
  });
  if (!smartlist_len(routers)) {
    connection_write_str_to_buf("512 No router names provided\r\n", conn);
    goto done;
  }

  if (zero_circ) {
    /* start a new circuit */
    circ = origin_circuit_init(intended_purpose, 0, 0, 0, 0);
  }

  /* now circ refers to something that is ready to be extended */
  SMARTLIST_FOREACH(routers, routerinfo_t *, r,
  {
    extend_info_t *info = extend_info_from_router(r);
    circuit_append_new_exit(circ, info);
    extend_info_free(info);
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
    if (circ->_base.state == CIRCUIT_STATE_OPEN) {
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
    control_event_circuit_status(circ, CIRC_EVENT_LAUNCHED, 0);
 done:
  SMARTLIST_FOREACH(router_nicknames, char *, n, tor_free(n));
  smartlist_free(router_nicknames);
  if (routers)
    smartlist_free(routers);
  return 0;
}

/** Called when we get a SETCIRCUITPURPOSE (if <b>for_circuits</b>
 * is 1) or SETROUTERPURPOSE message. If we can find
 * the circuit/router and it's a valid purpose, change it. */
static int
handle_control_setpurpose(control_connection_t *conn, int for_circuits,
                          uint32_t len, const char *body)
{
  origin_circuit_t *circ = NULL;
  routerinfo_t *ri = NULL;
  uint8_t new_purpose;
  smartlist_t *args = smartlist_create();
  (void) len; /* body is nul-terminated, so it's safe to ignore the length. */
  smartlist_split_string(args, body, " ",
                         SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 0);
  if (smartlist_len(args)<2) {
    connection_printf_to_buf(conn,
                             "512 Missing argument to SET%sPURPOSE\r\n",
                             for_circuits ? "CIRCUIT" : "ROUTER");
    goto done;
  }

  if (for_circuits) {
    if (!(circ = get_circ(smartlist_get(args,0)))) {
      connection_printf_to_buf(conn, "552 Unknown circuit \"%s\"\r\n",
                               (char*)smartlist_get(args, 0));
      goto done;
    }
  } else {
    if (!(ri = router_get_by_nickname(smartlist_get(args,0), 0))) {
      connection_printf_to_buf(conn, "552 Unknown router \"%s\"\r\n",
                               (char*)smartlist_get(args, 0));
      goto done;
    }
  }

  {
    char *purp = smartlist_get(args,1);
    if (get_purpose(&purp, for_circuits, &new_purpose) < 0) {
      connection_printf_to_buf(conn, "552 Unknown purpose \"%s\"\r\n", purp);
      goto done;
    }
  }

  if (for_circuits)
    circ->_base.purpose = new_purpose;
  else
    ri->purpose = new_purpose;
  connection_write_str_to_buf("250 OK\r\n", conn);

done:
  SMARTLIST_FOREACH(args, char *, cp, tor_free(cp));
  smartlist_free(args);
  return 0;
}

/** Called when we get an ATTACHSTREAM message.  Try to attach the requested
 * stream, and report success or failure. */
static int
handle_control_attachstream(control_connection_t *conn, uint32_t len,
                            const char *body)
{
  edge_connection_t *ap_conn = NULL;
  origin_circuit_t *circ = NULL;
  int zero_circ;
  (void) len;

  if (1) {
    smartlist_t *args;
    args = smartlist_create();
    smartlist_split_string(args, body, " ",
                           SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 0);
    if (smartlist_len(args)<2) {
      connection_printf_to_buf(conn,
                               "512 Missing argument to ATTACHSTREAM\r\n");
      SMARTLIST_FOREACH(args, char *, cp, tor_free(cp));
      smartlist_free(args);
      return 0;
    }

    zero_circ = !strcmp("0", (char*)smartlist_get(args,1));

    if (!(ap_conn = get_stream(smartlist_get(args, 0)))) {
      connection_printf_to_buf(conn, "552 Unknown stream \"%s\"\r\n",
                               (char*)smartlist_get(args, 0));
    } else if (!zero_circ && !(circ = get_circ(smartlist_get(args, 1)))) {
      connection_printf_to_buf(conn, "552 Unknown circuit \"%s\"\r\n",
                               (char*)smartlist_get(args, 1));
    }
    SMARTLIST_FOREACH(args, char *, cp, tor_free(cp));
    smartlist_free(args);
    if (!ap_conn || (!zero_circ && !circ))
      return 0;
  }

  if (ap_conn->_base.state != AP_CONN_STATE_CONTROLLER_WAIT &&
      ap_conn->_base.state != AP_CONN_STATE_CONNECT_WAIT &&
      ap_conn->_base.state != AP_CONN_STATE_RESOLVE_WAIT) {
    connection_write_str_to_buf(
                    "555 Connection is not managed by controller.\r\n",
                    conn);
    return 0;
  }

  /* Do we need to detach it first? */
  if (ap_conn->_base.state != AP_CONN_STATE_CONTROLLER_WAIT) {
    circuit_t *tmpcirc = circuit_get_by_edge_conn(ap_conn);
    connection_edge_end(ap_conn, END_STREAM_REASON_TIMEOUT,
                        ap_conn->cpath_layer);
    /* Un-mark it as ending, since we're going to reuse it. */
    ap_conn->_base.edge_has_sent_end = 0;
    ap_conn->end_reason = 0;
    if (tmpcirc)
      circuit_detach_stream(tmpcirc,ap_conn);
    ap_conn->_base.state = AP_CONN_STATE_CONTROLLER_WAIT;
  }

  if (circ && (circ->_base.state != CIRCUIT_STATE_OPEN)) {
    connection_write_str_to_buf(
                    "551 Can't attach stream to non-open, origin circuit\r\n",
                    conn);
    return 0;
  }
  if (circ && circuit_get_cpath_len(circ) < 2) {
    connection_write_str_to_buf(
                    "551 Can't attach stream to one-hop circuit.\r\n", conn);
    return 0;
  }
  if (connection_ap_handshake_rewrite_and_attach(ap_conn, circ) < 0) {
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

  if (1) {
    char *cp = memchr(body, '\n', len);
    smartlist_t *args = smartlist_create();
    tor_assert(cp);
    *cp++ = '\0';
    smartlist_split_string(args, body, " ",
                           SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 0);
    if (smartlist_len(args)) {
      char *purp = smartlist_get(args,0);
      if (get_purpose(&purp, 0, &purpose) < 0) {
        connection_printf_to_buf(conn, "552 Unknown purpose \"%s\"\r\n",
                                 purp);
        SMARTLIST_FOREACH(args, char *, cp, tor_free(cp));
        smartlist_free(args);
        return 0;
      }
    }
    SMARTLIST_FOREACH(args, char *, cp, tor_free(cp));
    smartlist_free(args);
    read_escaped_data(cp, len-(cp-body), 1, &desc);
  }

  switch (router_load_single_router(desc, purpose, &msg)) {
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
  return 0;
}

/** Called when we receive a REDIRECTSTERAM command.  Try to change the target
 * address of the named AP stream, and report success or failure. */
static int
handle_control_redirectstream(control_connection_t *conn, uint32_t len,
                              const char *body)
{
  edge_connection_t *ap_conn = NULL;
  char *new_addr = NULL;
  uint16_t new_port = 0;
  (void) len;

  if (1) {
    smartlist_t *args;
    args = smartlist_create();
    smartlist_split_string(args, body, " ",
                           SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 0);
    if (smartlist_len(args) < 2)
      connection_printf_to_buf(conn,
                               "512 Missing argument to REDIRECTSTREAM\r\n");
    else if (!(ap_conn = get_stream(smartlist_get(args, 0)))
             || !ap_conn->socks_request) {
      connection_printf_to_buf(conn, "552 Unknown stream \"%s\"\r\n",
                               (char*)smartlist_get(args, 0));
    } else {
      int ok;
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
  }

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
  edge_connection_t *ap_conn=NULL;
  uint8_t reason=0;
  (void) len;

  if (1) {
    smartlist_t *args;
    int ok;
    args = smartlist_create();
    smartlist_split_string(args, body, " ",
                           SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 0);
    if (smartlist_len(args)<2)
      connection_printf_to_buf(conn,
                               "512 Missing argument to CLOSESTREAM\r\n");
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
  }

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
  (void) len;

  if (1) {
    smartlist_t *args;
    args = smartlist_create();
    smartlist_split_string(args, body, " ",
                           SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 0);
    if (smartlist_len(args)<1)
      connection_printf_to_buf(conn,
                               "512 Missing argument to CLOSECIRCUIT\r\n");
    else if (!(circ=get_circ(smartlist_get(args, 0))))
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
  }

  if (!safe || !circ->p_streams) {
    circuit_mark_for_close(TO_CIRCUIT(circ), END_CIRC_REASON_REQUESTED);
  }

  send_control_done(conn);
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
  int verbose_names = 0, extended_events = 0;
  int bad = 0;
  (void) len; /* body is nul-terminated; it's safe to ignore the length */
  args = smartlist_create();
  smartlist_split_string(args, body, " ",
                         SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 0);
  SMARTLIST_FOREACH(args, const char *, arg, {
      if (!strcasecmp(arg, "VERBOSE_NAMES"))
        verbose_names = 1;
      else if (!strcasecmp(arg, "EXTENDED_EVENTS")) /* <- documented */
        extended_events = 1;
      else if (!strcasecmp(arg, "EXTENDED_FORMAT")) {
        /* remove this in 0.1.2.4; EXTENDED_FORMAT only ever worked for a
         * little while during 0.1.2.2-alpha-dev. */
        log_warn(LD_GENERAL,
                 "EXTENDED_FORMAT is deprecated; use EXTENDED_EVENTS "
                 "instead.");
        extended_events = 1;
      } else {
        connection_printf_to_buf(conn, "552 Unrecognized feature \"%s\"\r\n",
                                 arg);
        bad = 1;
        break;
      }
    });

  if (!bad) {
    if (verbose_names) {
      conn->use_long_names = 1;
      control_update_global_event_mask();
    }
    if (extended_events)
      conn->use_extended_events = 1;
    send_control_done(conn);
  }

  SMARTLIST_FOREACH(args, char *, cp, tor_free(cp));
  smartlist_free(args);
  return 0;
}

/** Called when <b>conn</b> has no more bytes left on its outbuf. */
int
connection_control_finished_flushing(control_connection_t *conn)
{
  tor_assert(conn);

  connection_stop_writing(TO_CONN(conn));
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

/** Called when data has arrived on a v1 control connection: Try to fetch
 * commands from conn->inbuf, and execute them.
 */
int
connection_control_process_inbuf(control_connection_t *conn)
{
  size_t data_len;
  int cmd_len;
  char *args;

  tor_assert(conn);
  tor_assert(conn->_base.state == CONTROL_CONN_STATE_OPEN ||
             conn->_base.state == CONTROL_CONN_STATE_NEEDAUTH);

  if (!conn->incoming_cmd) {
    conn->incoming_cmd = tor_malloc(1024);
    conn->incoming_cmd_len = 1024;
    conn->incoming_cmd_cur_len = 0;
  }

  if (conn->_base.state == CONTROL_CONN_STATE_NEEDAUTH &&
      peek_buf_has_control0_command(conn->_base.inbuf)) {
    /* Detect v0 commands and send a "no more v0" message. */
    size_t body_len;
    char buf[128];
    set_uint16(buf+2, htons(0x0000)); /* type == error */
    set_uint16(buf+4, htons(0x0001)); /* code == internal error */
    strlcpy(buf+6, "The v0 control protocol no longer supported in "VERSION"; "
            "use Tor 0.1.2.x or upgrade your controller", sizeof(buf)-6);
    body_len = 2+strlen(buf+6)+2; /* code, msg, nul. */
    set_uint16(buf+0, htons(body_len));
    connection_write_to_buf(buf, 4+body_len, TO_CONN(conn));
    connection_mark_for_close(TO_CONN(conn));
    conn->_base.hold_open_until_flushed = 1;
    return 0;
  }

 again:
  while (1) {
    size_t last_idx;
    int r;
    /* First, fetch a line. */
    do {
      data_len = conn->incoming_cmd_len - conn->incoming_cmd_cur_len;
      r = fetch_from_buf_line(conn->_base.inbuf,
                              conn->incoming_cmd+conn->incoming_cmd_cur_len,
                              &data_len);
      if (r == 0)
        /* Line not all here yet. Wait. */
        return 0;
      else if (r == -1) {
          while (conn->incoming_cmd_len < data_len+conn->incoming_cmd_cur_len)
            conn->incoming_cmd_len *= 2;
          conn->incoming_cmd = tor_realloc(conn->incoming_cmd,
                                           conn->incoming_cmd_len);
      }
    } while (r != 1);

    tor_assert(data_len);

    last_idx = conn->incoming_cmd_cur_len;
    conn->incoming_cmd_cur_len += data_len;

    /* We have appended a line to incoming_cmd.  Is the command done? */
    if (last_idx == 0 && *conn->incoming_cmd != '+')
      /* One line command, didn't start with '+'. */
      break;
    if (last_idx+3 == conn->incoming_cmd_cur_len &&
        !memcmp(conn->incoming_cmd + last_idx, ".\r\n", 3)) {
      /* Just appended ".\r\n"; we're done. Remove it. */
      conn->incoming_cmd_cur_len -= 3;
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

  data_len -= cmd_len;
  conn->incoming_cmd[cmd_len]='\0';
  args = conn->incoming_cmd+cmd_len+1;
  while (*args == ' ' || *args == '\t') {
    ++args;
    --data_len;
  }

  if (!strcasecmp(conn->incoming_cmd, "QUIT")) {
    connection_write_str_to_buf("250 closing connection\r\n", conn);
    connection_mark_for_close(TO_CONN(conn));
    return 0;
  }

  if (conn->_base.state == CONTROL_CONN_STATE_NEEDAUTH &&
      strcasecmp(conn->incoming_cmd, "AUTHENTICATE")) {
    connection_write_str_to_buf("514 Authentication required.\r\n", conn);
    conn->incoming_cmd_cur_len = 0;
    goto again;
  }

  if (!strcasecmp(conn->incoming_cmd, "SETCONF")) {
    if (handle_control_setconf(conn, data_len, args))
      return -1;
  } else if (!strcasecmp(conn->incoming_cmd, "RESETCONF")) {
    if (handle_control_resetconf(conn, data_len, args))
      return -1;
  } else if (!strcasecmp(conn->incoming_cmd, "GETCONF")) {
    if (handle_control_getconf(conn, data_len, args))
      return -1;
  } else if (!strcasecmp(conn->incoming_cmd, "SETEVENTS")) {
    if (handle_control_setevents(conn, data_len, args))
      return -1;
  } else if (!strcasecmp(conn->incoming_cmd, "AUTHENTICATE")) {
    if (handle_control_authenticate(conn, data_len, args))
      return -1;
  } else if (!strcasecmp(conn->incoming_cmd, "SAVECONF")) {
    if (handle_control_saveconf(conn, data_len, args))
      return -1;
  } else if (!strcasecmp(conn->incoming_cmd, "SIGNAL")) {
    if (handle_control_signal(conn, data_len, args))
      return -1;
  } else if (!strcasecmp(conn->incoming_cmd, "MAPADDRESS")) {
    if (handle_control_mapaddress(conn, data_len, args))
      return -1;
  } else if (!strcasecmp(conn->incoming_cmd, "GETINFO")) {
    if (handle_control_getinfo(conn, data_len, args))
      return -1;
  } else if (!strcasecmp(conn->incoming_cmd, "EXTENDCIRCUIT")) {
    if (handle_control_extendcircuit(conn, data_len, args))
      return -1;
  } else if (!strcasecmp(conn->incoming_cmd, "SETCIRCUITPURPOSE")) {
    if (handle_control_setpurpose(conn, 1, data_len, args))
      return -1;
  } else if (!strcasecmp(conn->incoming_cmd, "SETROUTERPURPOSE")) {
    if (handle_control_setpurpose(conn, 0, data_len, args))
      return -1;
  } else if (!strcasecmp(conn->incoming_cmd, "ATTACHSTREAM")) {
    if (handle_control_attachstream(conn, data_len, args))
      return -1;
  } else if (!strcasecmp(conn->incoming_cmd, "+POSTDESCRIPTOR")) {
    if (handle_control_postdescriptor(conn, data_len, args))
      return -1;
  } else if (!strcasecmp(conn->incoming_cmd, "REDIRECTSTREAM")) {
    if (handle_control_redirectstream(conn, data_len, args))
      return -1;
  } else if (!strcasecmp(conn->incoming_cmd, "CLOSESTREAM")) {
    if (handle_control_closestream(conn, data_len, args))
      return -1;
  } else if (!strcasecmp(conn->incoming_cmd, "CLOSECIRCUIT")) {
    if (handle_control_closecircuit(conn, data_len, args))
      return -1;
  } else if (!strcasecmp(conn->incoming_cmd, "USEFEATURE")) {
    if (handle_control_usefeature(conn, data_len, args))
      return -1;
  } else {
    connection_printf_to_buf(conn, "510 Unrecognized command \"%s\"\r\n",
                             conn->incoming_cmd);
  }

  conn->incoming_cmd_cur_len = 0;
  goto again;
}

/** Convert a numeric reason for destroying a circuit into a string for a
 * CIRCUIT event. */
static const char *
circuit_end_reason_to_string(int reason)
{
  if (reason >= 0 && reason & END_CIRC_REASON_FLAG_REMOTE)
    reason &= ~END_CIRC_REASON_FLAG_REMOTE;
  switch (reason) {
    case END_CIRC_AT_ORIGIN:
      /* This shouldn't get passed here; it's a catch-all reason. */
      return "ORIGIN";
    case END_CIRC_REASON_NONE:
      /* This shouldn't get passed here; it's a catch-all reason. */
      return "NONE";
    case END_CIRC_REASON_TORPROTOCOL:
      return "TORPROTOCOL";
    case END_CIRC_REASON_INTERNAL:
      return "INTERNAL";
    case END_CIRC_REASON_REQUESTED:
      return "REQUESTED";
    case END_CIRC_REASON_HIBERNATING:
      return "HIBERNATING";
    case END_CIRC_REASON_RESOURCELIMIT:
      return "RESOURCELIMIT";
    case END_CIRC_REASON_CONNECTFAILED:
      return "CONNECTFAILED";
    case END_CIRC_REASON_OR_IDENTITY:
      return "OR_IDENTITY";
    case END_CIRC_REASON_OR_CONN_CLOSED:
      return "OR_CONN_CLOSED";
    case END_CIRC_REASON_FINISHED:
      return "FINISHED";
    case END_CIRC_REASON_TIMEOUT:
      return "TIMEOUT";
    case END_CIRC_REASON_DESTROYED:
      return "DESTROYED";
    case END_CIRC_REASON_NOPATH:
      return "NOPATH";
    case END_CIRC_REASON_NOSUCHSERVICE:
      return "NOSUCHSERVICE";
    default:
      log_warn(LD_BUG, "Unrecognized reason code %d", (int)reason);
      return NULL;
  }
}

/** Something has happened to circuit <b>circ</b>: tell any interested
 * control connections. */
int
control_event_circuit_status(origin_circuit_t *circ, circuit_status_event_t tp,
                             int reason_code)
{
  char *path=NULL;
  if (!EVENT_IS_INTERESTING(EVENT_CIRCUIT_STATUS))
    return 0;
  tor_assert(circ);

  if (EVENT_IS_INTERESTING1S(EVENT_CIRCUIT_STATUS))
    path = circuit_list_path(circ,0);

  if (1) {
    const char *status;
    char reason_buf[64];
    int providing_reason=0;
    switch (tp)
      {
      case CIRC_EVENT_LAUNCHED: status = "LAUNCHED"; break;
      case CIRC_EVENT_BUILT: status = "BUILT"; break;
      case CIRC_EVENT_EXTENDED: status = "EXTENDED"; break;
      case CIRC_EVENT_FAILED: status = "FAILED"; break;
      case CIRC_EVENT_CLOSED: status = "CLOSED"; break;
      default:
        log_warn(LD_BUG, "Unrecognized status code %d", (int)tp);
        return 0;
      }

    if (tp == CIRC_EVENT_FAILED || tp == CIRC_EVENT_CLOSED) {
      const char *reason_str = circuit_end_reason_to_string(reason_code);
      char *reason = NULL;
      providing_reason=1;
      if (!reason_str) {
        reason = tor_malloc(16);
        tor_snprintf(reason, 16, "UNKNOWN_%d", reason_code);
        reason_str = reason;
      }
      if (reason_code > 0 && reason_code & END_CIRC_REASON_FLAG_REMOTE) {
        tor_snprintf(reason_buf, sizeof(reason_buf),
                     "REASON=DESTROYED REMOTE_REASON=%s", reason_str);
      } else {
        tor_snprintf(reason_buf, sizeof(reason_buf),
                     "REASON=%s", reason_str);
      }
      tor_free(reason);
    }

    if (EVENT_IS_INTERESTING1S(EVENT_CIRCUIT_STATUS)) {
      const char *sp = strlen(path) ? " " : "";
      if (providing_reason)
        send_control_event_extended(EVENT_CIRCUIT_STATUS, SHORT_NAMES,
                            "650 CIRC %lu %s%s%s@%s\r\n",
                            (unsigned long)circ->global_identifier,
                            status, sp, path, reason_buf);
      else
        send_control_event_extended(EVENT_CIRCUIT_STATUS, SHORT_NAMES,
                            "650 CIRC %lu %s%s%s\r\n",
                            (unsigned long)circ->global_identifier,
                            status, sp, path);
    }
    if (EVENT_IS_INTERESTING1L(EVENT_CIRCUIT_STATUS)) {
      char *vpath = circuit_list_path_for_controller(circ);
      const char *sp = strlen(vpath) ? " " : "";
      if (providing_reason)
        send_control_event_extended(EVENT_CIRCUIT_STATUS, LONG_NAMES,
                            "650 CIRC %lu %s%s%s@%s\r\n",
                            (unsigned long)circ->global_identifier,
                            status, sp, vpath, reason_buf);
      else
        send_control_event_extended(EVENT_CIRCUIT_STATUS, LONG_NAMES,
                            "650 CIRC %lu %s%s%s\r\n",
                            (unsigned long)circ->global_identifier,
                            status, sp, vpath);
      tor_free(vpath);
    }
  }
  tor_free(path);

  return 0;
}

/** Given an AP connection <b>conn</b> and a <b>len</b>-character buffer
 * <b>buf</b>, determine the address:port combination requested on
 * <b>conn</b>, and write it to <b>buf</b>.  Return 0 on success, -1 on
 * failure. */
static int
write_stream_target_to_buf(edge_connection_t *conn, char *buf, size_t len)
{
  char buf2[256];
  if (conn->chosen_exit_name)
    if (tor_snprintf(buf2, sizeof(buf2), ".%s.exit", conn->chosen_exit_name)<0)
      return -1;
  if (tor_snprintf(buf, len, "%s%s%s:%d",
               conn->socks_request->address,
               conn->chosen_exit_name ? buf2 : "",
               !conn->chosen_exit_name &&
                 connection_edge_is_rendezvous_stream(conn) ? ".onion" : "",
               conn->socks_request->port)<0)
    return -1;
  return 0;
}

/** Convert the reason for ending a stream <b>reason</b> into the format used
 * in STREAM events. Return NULL if the reason is unrecognized. */
static const char *
stream_end_reason_to_string(int reason)
{
  reason &= END_STREAM_REASON_MASK;
  switch (reason) {
    case END_STREAM_REASON_MISC: return "MISC";
    case END_STREAM_REASON_RESOLVEFAILED: return "RESOLVEFAILED";
    case END_STREAM_REASON_CONNECTREFUSED: return "CONNECTREFUSED";
    case END_STREAM_REASON_EXITPOLICY: return "EXITPOLICY";
    case END_STREAM_REASON_DESTROY: return "DESTROY";
    case END_STREAM_REASON_DONE: return "DONE";
    case END_STREAM_REASON_TIMEOUT: return "TIMEOUT";
    case END_STREAM_REASON_HIBERNATING: return "HIBERNATING";
    case END_STREAM_REASON_INTERNAL: return "INTERNAL";
    case END_STREAM_REASON_RESOURCELIMIT: return "RESOURCELIMIT";
    case END_STREAM_REASON_CONNRESET: return "CONNRESET";
    case END_STREAM_REASON_TORPROTOCOL: return "TORPROTOCOL";
    case END_STREAM_REASON_NOTDIRECTORY: return "NOTDIRECTORY";

    case END_STREAM_REASON_CANT_ATTACH: return "CANT_ATTACH";
    case END_STREAM_REASON_NET_UNREACHABLE: return "NET_UNREACHABLE";
    case END_STREAM_REASON_SOCKSPROTOCOL: return "SOCKS_PROTOCOL";

    default: return NULL;
  }
}

/** Something has happened to the stream associated with AP connection
 * <b>conn</b>: tell any interested control connections. */
int
control_event_stream_status(edge_connection_t *conn, stream_status_event_t tp,
                            int reason_code)
{
  char buf[256];
  tor_assert(conn->socks_request);

  if (!EVENT_IS_INTERESTING(EVENT_STREAM_STATUS))
    return 0;

  if (tp == STREAM_EVENT_CLOSED &&
      (reason_code & END_STREAM_REASON_FLAG_ALREADY_SENT_CLOSED))
    return 0;

  write_stream_target_to_buf(conn, buf, sizeof(buf));

  if (1) {
    char reason_buf[64];
    const char *status;
    circuit_t *circ;
    origin_circuit_t *origin_circ = NULL;
    reason_buf[0] = '\0';
    switch (tp)
      {
      case STREAM_EVENT_SENT_CONNECT: status = "SENTCONNECT"; break;
      case STREAM_EVENT_SENT_RESOLVE: status = "SENTRESOLVE"; break;
      case STREAM_EVENT_SUCCEEDED: status = "SUCCEEDED"; break;
      case STREAM_EVENT_FAILED: status = "FAILED"; break;
      case STREAM_EVENT_CLOSED: status = "CLOSED"; break;
      case STREAM_EVENT_NEW: status = "NEW"; break;
      case STREAM_EVENT_NEW_RESOLVE: status = "NEWRESOLVE"; break;
      case STREAM_EVENT_FAILED_RETRIABLE: status = "DETACHED"; break;
      case STREAM_EVENT_REMAP: status = "REMAP"; break;
      default:
        log_warn(LD_BUG, "Unrecognized status code %d", (int)tp);
        return 0;
      }
    if (reason_code && (tp == STREAM_EVENT_FAILED ||
                        tp == STREAM_EVENT_CLOSED ||
                        tp == STREAM_EVENT_FAILED_RETRIABLE)) {
      const char *reason_str = stream_end_reason_to_string(reason_code);
      char *r = NULL;
      if (!reason_str) {
        r = tor_malloc(16);
        tor_snprintf(r, 16, "UNKNOWN_%d", reason_code);
        reason_str = r;
      }
      if (reason_code & END_STREAM_REASON_FLAG_REMOTE)
        tor_snprintf(reason_buf, sizeof(reason_buf),
                     "REASON=END REMOTE_REASON=%s", reason_str);
      else
        tor_snprintf(reason_buf, sizeof(reason_buf),
                     "REASON=%s", reason_str);
      tor_free(r);
    } else if (reason_code && tp == STREAM_EVENT_REMAP) {
      switch (reason_code) {
        case REMAP_STREAM_SOURCE_CACHE:
          strlcpy(reason_buf, "SOURCE=CACHE", sizeof(reason_buf));
          break;
        case REMAP_STREAM_SOURCE_EXIT:
          strlcpy(reason_buf, "SOURCE=EXIT", sizeof(reason_buf));
          break;
        default:
          tor_snprintf(reason_buf, sizeof(reason_buf), "REASON=UNKNOWN_%d",
                       reason_code);
          break;
      }
    }
    circ = circuit_get_by_edge_conn(conn);
    if (circ && CIRCUIT_IS_ORIGIN(circ))
      origin_circ = TO_ORIGIN_CIRCUIT(circ);
    send_control_event_extended(EVENT_STREAM_STATUS, ALL_NAMES,
                        "650 STREAM %lu %s %lu %s@%s\r\n",
                        (unsigned long)conn->global_identifier, status,
                        origin_circ?
                           (unsigned long)origin_circ->global_identifier : 0ul,
                        buf, reason_buf);
    /* XXX need to specify its intended exit, etc? */
  }
  return 0;
}

/** Figure out the best name for the target router of an OR connection
 * <b>conn</b>, and write it into the <b>len</b>-character buffer
 * <b>name</b>.  Use verbose names if <b>long_names</b> is set. */
static void
orconn_target_get_name(int long_names,
                       char *name, size_t len, or_connection_t *conn)
{
  if (! long_names) {
    if (conn->nickname)
      strlcpy(name, conn->nickname, len);
    else
      tor_snprintf(name, len, "%s:%d",
                   conn->_base.address, conn->_base.port);
  } else {
    routerinfo_t *ri = router_get_by_digest(conn->identity_digest);
    if (ri) {
      tor_assert(len > MAX_VERBOSE_NICKNAME_LEN);
      router_get_verbose_nickname(name, ri);
    } else if (! tor_digest_is_zero(conn->identity_digest)) {
      name[0] = '$';
      base16_encode(name+1, len-1, conn->identity_digest,
                    DIGEST_LEN);
    } else {
     tor_snprintf(name, len, "%s:%d",
                   conn->_base.address, conn->_base.port);
    }
  }
}

/** Convert a TOR_TLS_* error code into an END_OR_CONN_* reason. */
int
control_tls_error_to_reason(int e)
{
  switch (e) {
    case TOR_TLS_ERROR_IO:
      return END_OR_CONN_REASON_TLS_IO_ERROR;
    case TOR_TLS_ERROR_CONNREFUSED:
      return END_OR_CONN_REASON_TCP_REFUSED;
    case TOR_TLS_ERROR_CONNRESET:
      return END_OR_CONN_REASON_TLS_CONNRESET;
    case TOR_TLS_ERROR_NO_ROUTE:
      return END_OR_CONN_REASON_TLS_NO_ROUTE;
    case TOR_TLS_ERROR_TIMEOUT:
      return END_OR_CONN_REASON_TLS_TIMEOUT;
    case TOR_TLS_WANTREAD:
    case TOR_TLS_WANTWRITE:
    case TOR_TLS_CLOSE:
    case TOR_TLS_DONE:
      return END_OR_CONN_REASON_DONE;
    default:
      return END_OR_CONN_REASON_TLS_MISC;
  }
}

/** Convert the reason for ending an OR connection <b>r</b> into the format
 * used in ORCONN events. Return NULL if the reason is unrecognized. */
static const char *
or_conn_end_reason_to_string(int r)
{
  switch (r) {
    case END_OR_CONN_REASON_DONE:
      return "REASON=DONE";
    case END_OR_CONN_REASON_TCP_REFUSED:
      return "REASON=CONNECTREFUSED";
    case END_OR_CONN_REASON_OR_IDENTITY:
      return "REASON=IDENTITY";
    case END_OR_CONN_REASON_TLS_CONNRESET:
      return "REASON=CONNECTRESET";
    case END_OR_CONN_REASON_TLS_TIMEOUT:
      return "REASON=TIMEOUT";
    case END_OR_CONN_REASON_TLS_NO_ROUTE:
      return "REASON=NOROUTE";
    case END_OR_CONN_REASON_TLS_IO_ERROR:
      return "REASON=IOERROR";
    case END_OR_CONN_REASON_TLS_MISC:
      return "REASON=MISC";
    case 0:
      return "";
    default:
      log_warn(LD_BUG, "Unrecognized or_conn reason code %d", r);
      return "REASON=BOGUS";
  }
}

/** Called when the status of an OR connection <b>conn</b> changes: tell any
 * interested control connections. <b>tp</b> is the new status for the
 * connection.  If <b>conn</b> has just closed or failed, then <b>reason</b>
 * may be the reason why.
 */
int
control_event_or_conn_status(or_connection_t *conn, or_conn_status_event_t tp,
                             int reason)
{
  int ncircs = 0;

  if (!EVENT_IS_INTERESTING(EVENT_OR_CONN_STATUS))
    return 0;

  if (1) {
    const char *status;
    char name[128];
    char ncircs_buf[32] = {0}; /* > 8 + log10(2^32)=10 + 2 */
    switch (tp)
      {
      case OR_CONN_EVENT_LAUNCHED: status = "LAUNCHED"; break;
      case OR_CONN_EVENT_CONNECTED: status = "CONNECTED"; break;
      case OR_CONN_EVENT_FAILED: status = "FAILED"; break;
      case OR_CONN_EVENT_CLOSED: status = "CLOSED"; break;
      case OR_CONN_EVENT_NEW: status = "NEW"; break;
      default:
        log_warn(LD_BUG, "Unrecognized status code %d", (int)tp);
        return 0;
      }
    ncircs = circuit_count_pending_on_or_conn(conn);
    ncircs += conn->n_circuits;
    if (ncircs && (tp == OR_CONN_EVENT_FAILED || tp == OR_CONN_EVENT_CLOSED)) {
        tor_snprintf(ncircs_buf, sizeof(ncircs_buf), "%sNCIRCS=%d",
                reason ? " " : "", ncircs);
    }

    if (EVENT_IS_INTERESTING1S(EVENT_OR_CONN_STATUS)) {
      orconn_target_get_name(0, name, sizeof(name), conn);
      send_control_event_extended(EVENT_OR_CONN_STATUS, SHORT_NAMES,
                          "650 ORCONN %s %s@%s%s\r\n",
                          name, status,
                          or_conn_end_reason_to_string(reason), ncircs_buf);
    }
    if (EVENT_IS_INTERESTING1L(EVENT_OR_CONN_STATUS)) {
      orconn_target_get_name(1, name, sizeof(name), conn);
      send_control_event_extended(EVENT_OR_CONN_STATUS, LONG_NAMES,
                          "650 ORCONN %s %s@%s%s\r\n",
                          name, status,
                          or_conn_end_reason_to_string(reason), ncircs_buf);
    }
  }
  return 0;
}

/** A second or more has elapsed: tell any interested control
 * connections how much bandwidth streams have used. */
int
control_event_stream_bandwidth_used(void)
{
  connection_t **carray;
  edge_connection_t *conn;
  int n, i;

  if (EVENT_IS_INTERESTING(EVENT_STREAM_BANDWIDTH_USED)) {
    get_connection_array(&carray, &n);

    for (i = 0; i < n; ++i) {
        if (carray[i]->type != CONN_TYPE_AP)
          continue;
        conn = TO_EDGE_CONN(carray[i]);
        if (!conn->n_read && !conn->n_written)
          continue;

        send_control_event(EVENT_STREAM_BANDWIDTH_USED, ALL_NAMES,
                            "650 STREAM_BW %lu %lu %lu\r\n",
                            (unsigned long)conn->global_identifier,
                            (unsigned long)conn->n_read,
                            (unsigned long)conn->n_written);

        conn->n_written = conn->n_read = 0;
    }
  }

  return 0;
}

/** A second or more has elapsed: tell any interested control
 * connections how much bandwidth we used. */
int
control_event_bandwidth_used(uint32_t n_read, uint32_t n_written)
{
  if (EVENT_IS_INTERESTING(EVENT_BANDWIDTH_USED)) {
    send_control_event(EVENT_BANDWIDTH_USED, ALL_NAMES,
                        "650 BW %lu %lu\r\n",
                        (unsigned long)n_read,
                        (unsigned long)n_written);
  }

  return 0;
}

/** Called when we are sending a log message to the controllers: suspend
 * sending further log messages to the controllers until we're done.  Used by
 * CONN_LOG_PROTECT. */
void
disable_control_logging(void)
{
  ++disable_log_messages;
}

/** We're done sending a log message to the controllers: re-enable controller
 * logging.  Used by CONN_LOG_PROTECT. */
void
enable_control_logging(void)
{
  if (--disable_log_messages < 0)
    tor_assert(0);
}

/** We got a log message: tell any interested control connections. */
void
control_event_logmsg(int severity, uint32_t domain, const char *msg)
{
  int event;

  if (disable_log_messages)
    return;

  if (domain == LD_BUG && EVENT_IS_INTERESTING(EVENT_STATUS_GENERAL) &&
      severity <= LOG_NOTICE) {
    char *esc = esc_for_log(msg);
    ++disable_log_messages;
    control_event_general_status(severity, "BUG REASON=\"%s\"", esc);
    --disable_log_messages;
    tor_free(esc);
  }

  event = log_severity_to_event(severity);
  if (event >= 0 && EVENT_IS_INTERESTING(event)) {
    char *b = NULL;
    const char *s;
    if (strchr(msg, '\n')) {
      char *cp;
      b = tor_strdup(msg);
      for (cp = b; *cp; ++cp)
        if (*cp == '\r' || *cp == '\n')
          *cp = ' ';
    }
    switch (severity) {
      case LOG_DEBUG: s = "DEBUG"; break;
      case LOG_INFO: s = "INFO"; break;
      case LOG_NOTICE: s = "NOTICE"; break;
      case LOG_WARN: s = "WARN"; break;
      case LOG_ERR: s = "ERR"; break;
      default: s = "UnknownLogSeverity"; break;
    }
    ++disable_log_messages;
    send_control_event(event, ALL_NAMES, "650 %s %s\r\n", s, b?b:msg);
    --disable_log_messages;
    tor_free(b);
  }
}

/** Called whenever we receive new router descriptors: tell any
 * interested control connections.  <b>routers</b> is a list of
 * DIGEST_LEN-byte identity digests.
 */
int
control_event_descriptors_changed(smartlist_t *routers)
{
  size_t len;
  char *msg;
  smartlist_t *identities = NULL;
  char buf[HEX_DIGEST_LEN+1];

  if (!EVENT_IS_INTERESTING(EVENT_NEW_DESC))
    return 0;
  if (EVENT_IS_INTERESTING1S(EVENT_NEW_DESC)) {
    identities = smartlist_create();
    SMARTLIST_FOREACH(routers, routerinfo_t *, r,
    {
      base16_encode(buf,sizeof(buf),r->cache_info.identity_digest,DIGEST_LEN);
      smartlist_add(identities, tor_strdup(buf));
    });
  }
  if (EVENT_IS_INTERESTING1S(EVENT_NEW_DESC)) {
    char *ids = smartlist_join_strings(identities, " ", 0, &len);
    size_t len = strlen(ids)+32;
    msg = tor_malloc(len);
    tor_snprintf(msg, len, "650 NEWDESC %s\r\n", ids);
    send_control_event_string(EVENT_NEW_DESC, SHORT_NAMES|ALL_FORMATS, msg);
    tor_free(ids);
    tor_free(msg);
  }
  if (EVENT_IS_INTERESTING1L(EVENT_NEW_DESC)) {
    smartlist_t *names = smartlist_create();
    char *ids;
    size_t len;
    SMARTLIST_FOREACH(routers, routerinfo_t *, ri, {
        char *b = tor_malloc(MAX_VERBOSE_NICKNAME_LEN+1);
        router_get_verbose_nickname(b, ri);
        smartlist_add(names, b);
      });
    ids = smartlist_join_strings(names, " ", 0, &len);
    len = strlen(ids)+32;
    msg = tor_malloc(len);
    tor_snprintf(msg, len, "650 NEWDESC %s\r\n", ids);
    send_control_event_string(EVENT_NEW_DESC, LONG_NAMES|ALL_FORMATS, msg);
    tor_free(ids);
    tor_free(msg);
    SMARTLIST_FOREACH(names, char *, cp, tor_free(cp));
    smartlist_free(names);
  }
  if (identities) {
    SMARTLIST_FOREACH(identities, char *, cp, tor_free(cp));
    smartlist_free(identities);
  }
  return 0;
}

/** Called whenever an address mapping on <b>from<b> from changes to <b>to</b>.
 * <b>expires</b> values less than 3 are special; see connection_edge.c. */
int
control_event_address_mapped(const char *from, const char *to, time_t expires)
{
  if (!EVENT_IS_INTERESTING(EVENT_ADDRMAP))
    return 0;

  if (expires < 3)
    send_control_event(EVENT_ADDRMAP, ALL_NAMES,
                        "650 ADDRMAP %s %s NEVER\r\n", from, to);
  else {
    char buf[ISO_TIME_LEN+1];
    format_local_iso_time(buf,expires);
    send_control_event(EVENT_ADDRMAP, ALL_NAMES,
                        "650 ADDRMAP %s %s \"%s\"\r\n",
                        from, to, buf);
  }

  return 0;
}

/** The authoritative dirserver has received a new descriptor that
 * has passed basic syntax checks and is properly self-signed.
 *
 * Notify any interested party of the new descriptor and what has
 * been done with it, and also optionally give an explanation/reason. */
int
control_event_or_authdir_new_descriptor(const char *action,
                                        const char *descriptor,
                                        const char *msg)
{
  char firstline[1024];
  char *buf;
  int totallen;
  char *esc = NULL;
  size_t esclen;

  if (!EVENT_IS_INTERESTING(EVENT_AUTHDIR_NEWDESCS))
    return 0;

  tor_snprintf(firstline, sizeof(firstline),
               "650+AUTHDIR_NEWDESC=\r\n%s\r\n%s\r\n",
               action,
               msg ? msg : "");

  /* Escape the server descriptor properly */
  esclen = write_escaped_data(descriptor, strlen(descriptor), 1, &esc);

  totallen = strlen(firstline) + esclen + 1;
  buf = tor_malloc(totallen);
  strlcpy(buf, firstline, totallen);
  strlcpy(buf+strlen(firstline), esc, totallen);
  send_control_event_string(EVENT_AUTHDIR_NEWDESCS, ALL_NAMES|ALL_FORMATS,
                             buf);

  tor_free(esc);
  tor_free(buf);

  return 0;
}

/** Called when the local_routerstatus_ts <b>statuses</b> have changed: sends
 * an NS event to any controller that cares. */
int
control_event_networkstatus_changed(smartlist_t *statuses)
{
  smartlist_t *strs;
  char *s;
  if (!EVENT_IS_INTERESTING(EVENT_NS) || !smartlist_len(statuses))
    return 0;

  strs = smartlist_create();
  smartlist_add(strs, tor_strdup("650+NS\r\n"));
  SMARTLIST_FOREACH(statuses, local_routerstatus_t *, rs,
    {
      s = networkstatus_getinfo_helper_single(&rs->status);
      if (!s) continue;
      smartlist_add(strs, s);
    });
  smartlist_add(strs, tor_strdup("\r\n.\r\n"));

  s = smartlist_join_strings(strs, "", 0, NULL);
  SMARTLIST_FOREACH(strs, char *, cp, tor_free(cp));
  smartlist_free(strs);
  send_control_event_string(EVENT_NS, ALL_NAMES|ALL_FORMATS, s);
  tor_free(s);
  return 0;
}

/** Called when a single local_routerstatus_t has changed: Sends an NS event
 * to any countroller that cares. */
int
control_event_networkstatus_changed_single(local_routerstatus_t *rs)
{
  smartlist_t *statuses;
  int r;

  if (!EVENT_IS_INTERESTING(EVENT_NS))
    return 0;

  statuses = smartlist_create();
  smartlist_add(statuses, rs);
  r = control_event_networkstatus_changed(statuses);
  smartlist_free(statuses);
  return r;
}

/** Our own router descriptor has changed; tell any controllers that care.
 */
int
control_event_my_descriptor_changed(void)
{
  send_control_event(EVENT_DESCCHANGED, ALL_NAMES, "650 DESCCHANGED\r\n");
  return 0;
}

/** Helper: sends a status event where <b>type</b> is one of
 * EVENT_STATUS_{GENERAL,CLIENT,SERVER}, where <b>severity</b> is one of
 * LOG_{NOTICE,WARN,ERR}, and where <b>format</b> is a printf-style format
 * string corresponding to <b>args</b>. */
static int
control_event_status(int type, int severity, const char *format, va_list args)
{
  char format_buf[160];
  const char *status, *sev;

  switch (type) {
    case EVENT_STATUS_GENERAL:
      status = "STATUS_GENERAL";
      break;
    case EVENT_STATUS_CLIENT:
      status = "STATUS_CLIENT";
      break;
    case EVENT_STATUS_SERVER:
      status = "STATUS_SEVER";
      break;
    default:
      log_warn(LD_BUG, "Unrecognized status type %d", type);
      return -1;
  }
  switch (severity) {
    case LOG_NOTICE:
      sev = "NOTICE";
      break;
    case LOG_WARN:
      sev = "WARN";
      break;
    case LOG_ERR:
      sev = "ERR";
      break;
    default:
      log_warn(LD_BUG, "Unrecognized status severity %d", severity);
      return -1;
  }
  if (tor_snprintf(format_buf, sizeof(format_buf), "650 %s %s %s\r\n",
                   status, sev, format)<0) {
    log_warn(LD_BUG, "Format string too long.");
    return -1;
  }

  send_control_event_impl(type, ALL_NAMES|ALL_FORMATS, 0, format_buf, args);
  return 0;
}

/** Format and send an EVENT_STATUS_GENERAL event whose main text is obtained
 * by formatting the arguments using the printf-style <b>format</b>. */
int
control_event_general_status(int severity, const char *format, ...)
{
  va_list ap;
  int r;
  if (!EVENT_IS_INTERESTING(EVENT_STATUS_GENERAL))
    return 0;

  va_start(ap, format);
  r = control_event_status(EVENT_STATUS_GENERAL, severity, format, ap);
  va_end(ap);
  return r;
}

/** Format and send an EVENT_STATUS_CLIENT event whose main text is obtained
 * by formatting the arguments using the printf-style <b>format</b>. */
int
control_event_client_status(int severity, const char *format, ...)
{
  va_list ap;
  int r;
  if (!EVENT_IS_INTERESTING(EVENT_STATUS_CLIENT))
    return 0;

  va_start(ap, format);
  r = control_event_status(EVENT_STATUS_CLIENT, severity, format, ap);
  va_end(ap);
  return r;
}

/** Format and send an EVENT_STATUS_SERVER event whose main text is obtained
 * by formatting the arguments using the printf-style <b>format</b>. */
int
control_event_server_status(int severity, const char *format, ...)
{
  va_list ap;
  int r;
  if (!EVENT_IS_INTERESTING(EVENT_STATUS_SERVER))
    return 0;

  va_start(ap, format);
  r = control_event_status(EVENT_STATUS_SERVER, severity, format, ap);
  va_end(ap);
  return r;
}

/** Called when the status of an entry guard with the given <b>nickname</b>
 * and identity <b>digest</b> has changed to <b>status</b>: tells any
 * controllers that care. */
int
control_event_guard(const char *nickname, const char *digest,
                    const char *status)
{
  char hbuf[HEX_DIGEST_LEN+1];
  base16_encode(hbuf, sizeof(hbuf), digest, DIGEST_LEN);
  if (!EVENT_IS_INTERESTING(EVENT_GUARD))
    return 0;

  if (EVENT_IS_INTERESTING1L(EVENT_GUARD)) {
    char buf[MAX_VERBOSE_NICKNAME_LEN+1];
    routerinfo_t *ri = router_get_by_digest(digest);
    if (ri) {
      router_get_verbose_nickname(buf, ri);
    } else {
      tor_snprintf(buf, sizeof(buf), "$%s~%s", hbuf, nickname);
    }
    send_control_event(EVENT_GUARD, LONG_NAMES,
                        "650 GUARD ENTRY %s %s\r\n", buf, status);
  }
  if (EVENT_IS_INTERESTING1S(EVENT_GUARD)) {
    send_control_event(EVENT_GUARD, SHORT_NAMES,
                        "650 GUARD ENTRY $%s %s\r\n", hbuf, status);
  }
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

  tor_snprintf(fname, sizeof(fname), "%s"PATH_SEPARATOR"control_auth_cookie",
               get_options()->DataDirectory);
  crypto_rand(authentication_cookie, AUTHENTICATION_COOKIE_LEN);
  authentication_cookie_is_set = 1;
  if (write_bytes_to_file(fname, authentication_cookie,
                          AUTHENTICATION_COOKIE_LEN, 1)) {
    log_warn(LD_FS,"Error writing authentication cookie.");
    return -1;
  }

  return 0;
}

