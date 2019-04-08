/* Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2019, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file control.c
 * \brief Formatting functions for controller data.
 */

#include "core/or/or.h"

#include "core/mainloop/connection.h"
#include "core/or/circuitbuild.h"
#include "core/or/circuitlist.h"
#include "core/or/connection_edge.h"
#include "feature/control/control_fmt.h"
#include "feature/nodelist/nodelist.h"

#include "core/or/cpath_build_state_st.h"
#include "core/or/entry_connection_st.h"
#include "core/or/or_connection_st.h"
#include "core/or/origin_circuit_st.h"
#include "core/or/socks_request_st.h"
#include "feature/control/control_connection_st.h"

/** Append a NUL-terminated string <b>s</b> to the end of
 * <b>conn</b>-\>outbuf.
 */
void
connection_write_str_to_buf(const char *s, control_connection_t *conn)
{
  size_t len = strlen(s);
  connection_buf_add(s, len, TO_CONN(conn));
}

/** Acts like sprintf, but writes its formatted string to the end of
 * <b>conn</b>-\>outbuf. */
void
connection_printf_to_buf(control_connection_t *conn, const char *format, ...)
{
  va_list ap;
  char *buf = NULL;
  int len;

  va_start(ap,format);
  len = tor_vasprintf(&buf, format, ap);
  va_end(ap);

  if (len < 0) {
    log_err(LD_BUG, "Unable to format string for controller.");
    tor_assert(0);
  }

  connection_buf_add(buf, (size_t)len, TO_CONN(conn));

  tor_free(buf);
}

/** Given an AP connection <b>conn</b> and a <b>len</b>-character buffer
 * <b>buf</b>, determine the address:port combination requested on
 * <b>conn</b>, and write it to <b>buf</b>.  Return 0 on success, -1 on
 * failure. */
int
write_stream_target_to_buf(entry_connection_t *conn, char *buf, size_t len)
{
  char buf2[256];
  if (conn->chosen_exit_name)
    if (tor_snprintf(buf2, sizeof(buf2), ".%s.exit", conn->chosen_exit_name)<0)
      return -1;
  if (!conn->socks_request)
    return -1;
  if (tor_snprintf(buf, len, "%s%s%s:%d",
               conn->socks_request->address,
               conn->chosen_exit_name ? buf2 : "",
               !conn->chosen_exit_name && connection_edge_is_rendezvous_stream(
                                     ENTRY_TO_EDGE_CONN(conn)) ? ".onion" : "",
               conn->socks_request->port)<0)
    return -1;
  return 0;
}

/** Figure out the best name for the target router of an OR connection
 * <b>conn</b>, and write it into the <b>len</b>-character buffer
 * <b>name</b>. */
void
orconn_target_get_name(char *name, size_t len, or_connection_t *conn)
{
  const node_t *node = node_get_by_id(conn->identity_digest);
  if (node) {
    tor_assert(len > MAX_VERBOSE_NICKNAME_LEN);
    node_get_verbose_nickname(node, name);
  } else if (! tor_digest_is_zero(conn->identity_digest)) {
    name[0] = '$';
    base16_encode(name+1, len-1, conn->identity_digest,
                  DIGEST_LEN);
  } else {
    tor_snprintf(name, len, "%s:%d",
                 conn->base_.address, conn->base_.port);
  }
}

/** Allocate and return a description of <b>circ</b>'s current status,
 * including its path (if any). */
char *
circuit_describe_status_for_controller(origin_circuit_t *circ)
{
  char *rv;
  smartlist_t *descparts = smartlist_new();

  {
    char *vpath = circuit_list_path_for_controller(circ);
    if (*vpath) {
      smartlist_add(descparts, vpath);
    } else {
      tor_free(vpath); /* empty path; don't put an extra space in the result */
    }
  }

  {
    cpath_build_state_t *build_state = circ->build_state;
    smartlist_t *flaglist = smartlist_new();
    char *flaglist_joined;

    if (build_state->onehop_tunnel)
      smartlist_add(flaglist, (void *)"ONEHOP_TUNNEL");
    if (build_state->is_internal)
      smartlist_add(flaglist, (void *)"IS_INTERNAL");
    if (build_state->need_capacity)
      smartlist_add(flaglist, (void *)"NEED_CAPACITY");
    if (build_state->need_uptime)
      smartlist_add(flaglist, (void *)"NEED_UPTIME");

    /* Only emit a BUILD_FLAGS argument if it will have a non-empty value. */
    if (smartlist_len(flaglist)) {
      flaglist_joined = smartlist_join_strings(flaglist, ",", 0, NULL);

      smartlist_add_asprintf(descparts, "BUILD_FLAGS=%s", flaglist_joined);

      tor_free(flaglist_joined);
    }

    smartlist_free(flaglist);
  }

  smartlist_add_asprintf(descparts, "PURPOSE=%s",
                    circuit_purpose_to_controller_string(circ->base_.purpose));

  {
    const char *hs_state =
      circuit_purpose_to_controller_hs_state_string(circ->base_.purpose);

    if (hs_state != NULL) {
      smartlist_add_asprintf(descparts, "HS_STATE=%s", hs_state);
    }
  }

  if (circ->rend_data != NULL || circ->hs_ident != NULL) {
    char addr[HS_SERVICE_ADDR_LEN_BASE32 + 1];
    const char *onion_address;
    if (circ->rend_data) {
      onion_address = rend_data_get_address(circ->rend_data);
    } else {
      hs_build_address(&circ->hs_ident->identity_pk, HS_VERSION_THREE, addr);
      onion_address = addr;
    }
    smartlist_add_asprintf(descparts, "REND_QUERY=%s", onion_address);
  }

  {
    char tbuf[ISO_TIME_USEC_LEN+1];
    format_iso_time_nospace_usec(tbuf, &circ->base_.timestamp_created);

    smartlist_add_asprintf(descparts, "TIME_CREATED=%s", tbuf);
  }

  // Show username and/or password if available.
  if (circ->socks_username_len > 0) {
    char* socks_username_escaped = esc_for_log_len(circ->socks_username,
                                     (size_t) circ->socks_username_len);
    smartlist_add_asprintf(descparts, "SOCKS_USERNAME=%s",
                           socks_username_escaped);
    tor_free(socks_username_escaped);
  }
  if (circ->socks_password_len > 0) {
    char* socks_password_escaped = esc_for_log_len(circ->socks_password,
                                     (size_t) circ->socks_password_len);
    smartlist_add_asprintf(descparts, "SOCKS_PASSWORD=%s",
                           socks_password_escaped);
    tor_free(socks_password_escaped);
  }

  rv = smartlist_join_strings(descparts, " ", 0, NULL);

  SMARTLIST_FOREACH(descparts, char *, cp, tor_free(cp));
  smartlist_free(descparts);

  return rv;
}

/** Given a <b>len</b>-character string in <b>data</b>, made of lines
 * terminated by CRLF, allocate a new string in *<b>out</b>, and copy the
 * contents of <b>data</b> into *<b>out</b>, adding a period before any period
 * that appears at the start of a line, and adding a period-CRLF line at
 * the end. Replace all LF characters sequences with CRLF.  Return the number
 * of bytes in *<b>out</b>.
 */
size_t
write_escaped_data(const char *data, size_t len, char **out)
{
  tor_assert(len < SIZE_MAX - 9);
  size_t sz_out = len+8+1;
  char *outp;
  const char *start = data, *end;
  size_t i;
  int start_of_line;
  for (i=0; i < len; ++i) {
    if (data[i] == '\n') {
      sz_out += 2; /* Maybe add a CR; maybe add a dot. */
      if (sz_out >= SIZE_T_CEILING) {
        log_warn(LD_BUG, "Input to write_escaped_data was too long");
        *out = tor_strdup(".\r\n");
        return 3;
      }
    }
  }
  *out = outp = tor_malloc(sz_out);
  end = data+len;
  start_of_line = 1;
  while (data < end) {
    if (*data == '\n') {
      if (data > start && data[-1] != '\r')
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
  if (outp < *out+2 || fast_memcmp(outp-2, "\r\n", 2)) {
    *outp++ = '\r';
    *outp++ = '\n';
  }
  *outp++ = '.';
  *outp++ = '\r';
  *outp++ = '\n';
  *outp = '\0'; /* NUL-terminate just in case. */
  tor_assert(outp >= *out);
  tor_assert((size_t)(outp - *out) <= sz_out);
  return outp - *out;
}

/** Given a <b>len</b>-character string in <b>data</b>, made of lines
 * terminated by CRLF, allocate a new string in *<b>out</b>, and copy
 * the contents of <b>data</b> into *<b>out</b>, removing any period
 * that appears at the start of a line, and replacing all CRLF sequences
 * with LF.   Return the number of
 * bytes in *<b>out</b>. */
size_t
read_escaped_data(const char *data, size_t len, char **out)
{
  char *outp;
  const char *next;
  const char *end;

  *out = outp = tor_malloc(len+1);

  end = data+len;

  while (data < end) {
    /* we're at the start of a line. */
    if (*data == '.')
      ++data;
    next = memchr(data, '\n', end-data);
    if (next) {
      size_t n_to_copy = next-data;
      /* Don't copy a CR that precedes this LF. */
      if (n_to_copy && *(next-1) == '\r')
        --n_to_copy;
      memcpy(outp, data, n_to_copy);
      outp += n_to_copy;
      data = next+1; /* This will point at the start of the next line,
                      * or the end of the string, or a period. */
    } else {
      memcpy(outp, data, end-data);
      outp += (end-data);
      *outp = '\0';
      return outp - *out;
    }
    *outp++ = '\n';
  }

  *outp = '\0';
  return outp - *out;
}

/** Send a "DONE" message down the control connection <b>conn</b>. */
void
send_control_done(control_connection_t *conn)
{
  connection_write_str_to_buf("250 OK\r\n", conn);
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

/** Given a pointer to a string starting at <b>start</b> containing
 * <b>in_len_max</b> characters, decode a string beginning with one double
 * quote, containing any number of non-quote characters or characters escaped
 * with a backslash, and ending with a final double quote.  Place the resulting
 * string (unquoted, unescaped) into a newly allocated string in *<b>out</b>;
 * store its length in <b>out_len</b>.  On success, return a pointer to the
 * character immediately following the escaped string.  On failure, return
 * NULL. */
const char *
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
