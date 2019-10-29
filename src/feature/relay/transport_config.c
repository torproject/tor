/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2019, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * @file transport_config.c
 * @brief Code to interpret the user's configuration of Tor's server
 *        pluggable transports.
 **/

#include "orconfig.h"
#include "feature/relay/transport_config.h"

#include "lib/encoding/confline.h"
#include "lib/encoding/keyval.h"

#include "lib/container/smartlist.h"

/* Required for dirinfo_type_t in or_options_t */
#include "core/or/or.h"
#include "app/config/config.h"

#include "feature/relay/ext_orport.h"
#include "feature/relay/routermode.h"

/* Copied from config.c, we will refactor later in 29211. */
#define REJECT(arg) \
  STMT_BEGIN *msg = tor_strdup(arg); return -1; STMT_END

/** Given a ServerTransportListenAddr <b>line</b>, return its
 *  <address:port> string. Return NULL if the line was not
 *  well-formed.
 *
 *  If <b>transport</b> is set, return NULL if the line is not
 *  referring to <b>transport</b>.
 *
 *  The returned string is allocated on the heap and it's the
 *  responsibility of the caller to free it. */
static char *
get_bindaddr_from_transport_listen_line(const char *line,const char *transport)
{
  smartlist_t *items = NULL;
  const char *parsed_transport = NULL;
  char *addrport = NULL;
  tor_addr_t addr;
  uint16_t port = 0;

  items = smartlist_new();
  smartlist_split_string(items, line, NULL,
                         SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, -1);

  if (smartlist_len(items) < 2) {
    log_warn(LD_CONFIG,"Too few arguments on ServerTransportListenAddr line.");
    goto err;
  }

  parsed_transport = smartlist_get(items, 0);
  addrport = tor_strdup(smartlist_get(items, 1));

  /* If 'transport' is given, check if it matches the one on the line */
  if (transport && strcmp(transport, parsed_transport))
    goto err;

  /* Validate addrport */
  if (tor_addr_port_parse(LOG_WARN, addrport, &addr, &port, -1)<0) {
    log_warn(LD_CONFIG, "Error parsing ServerTransportListenAddr "
             "address '%s'", addrport);
    goto err;
  }

  goto done;

 err:
  tor_free(addrport);
  addrport = NULL;

 done:
  SMARTLIST_FOREACH(items, char*, s, tor_free(s));
  smartlist_free(items);

  return addrport;
}

/** Given the name of a pluggable transport in <b>transport</b>, check
 *  the configuration file to see if the user has explicitly asked for
 *  it to listen on a specific port. Return a <address:port> string if
 *  so, otherwise NULL. */
char *
get_transport_bindaddr_from_config(const char *transport)
{
  config_line_t *cl;
  const or_options_t *options = get_options();

  for (cl = options->ServerTransportListenAddr; cl; cl = cl->next) {
    char *bindaddr =
      get_bindaddr_from_transport_listen_line(cl->value, transport);
    if (bindaddr)
      return bindaddr;
  }

  return NULL;
}

/** Given a ServerTransportOptions <b>line</b>, return a smartlist
 *  with the options. Return NULL if the line was not well-formed.
 *
 *  If <b>transport</b> is set, return NULL if the line is not
 *  referring to <b>transport</b>.
 *
 *  The returned smartlist and its strings are allocated on the heap
 *  and it's the responsibility of the caller to free it. */
smartlist_t *
get_options_from_transport_options_line(const char *line,const char *transport)
{
  smartlist_t *items = smartlist_new();
  smartlist_t *options = smartlist_new();
  const char *parsed_transport = NULL;

  smartlist_split_string(items, line, NULL,
                         SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, -1);

  if (smartlist_len(items) < 2) {
    log_warn(LD_CONFIG,"Too few arguments on ServerTransportOptions line.");
    goto err;
  }

  parsed_transport = smartlist_get(items, 0);
  /* If 'transport' is given, check if it matches the one on the line */
  if (transport && strcmp(transport, parsed_transport))
    goto err;

  SMARTLIST_FOREACH_BEGIN(items, const char *, option) {
    if (option_sl_idx == 0) /* skip the transport field (first field)*/
      continue;

    /* validate that it's a k=v value */
    if (!string_is_key_value(LOG_WARN, option)) {
      log_warn(LD_CONFIG, "%s is not a k=v value.", escaped(option));
      goto err;
    }

    /* add it to the options smartlist */
    smartlist_add_strdup(options, option);
    log_debug(LD_CONFIG, "Added %s to the list of options", escaped(option));
  } SMARTLIST_FOREACH_END(option);

  goto done;

 err:
  SMARTLIST_FOREACH(options, char*, s, tor_free(s));
  smartlist_free(options);
  options = NULL;

 done:
  SMARTLIST_FOREACH(items, char*, s, tor_free(s));
  smartlist_free(items);

  return options;
}

/** Given the name of a pluggable transport in <b>transport</b>, check
 *  the configuration file to see if the user has asked us to pass any
 *  parameters to the pluggable transport. Return a smartlist
 *  containing the parameters, otherwise NULL. */
smartlist_t *
get_options_for_server_transport(const char *transport)
{
  config_line_t *cl;
  const or_options_t *options = get_options();

  for (cl = options->ServerTransportOptions; cl; cl = cl->next) {
    smartlist_t *options_sl =
      get_options_from_transport_options_line(cl->value, transport);
    if (options_sl)
      return options_sl;
  }

  return NULL;
}

/**
 * Legacy validation/normalization function for the server transport options.
 * Uses old_options as the previous options.
 *
 * Returns 0 on success, returns -1 and sets *msg to a newly allocated string
 * on error.
 */
int
options_validate_server_transport(const or_options_t *old_options,
                                  or_options_t *options,
                                  char **msg)
{
  (void)old_options;

  if (BUG(!options))
    return -1;

  if (BUG(!msg))
    return -1;

  config_line_t *cl;

  for (cl = options->ServerTransportPlugin; cl; cl = cl->next) {
    if (parse_transport_line(options, cl->value, 1, 1) < 0)
      REJECT("Invalid server transport line. See logs for details.");
  }

  if (options->ServerTransportPlugin && !server_mode(options)) {
    log_notice(LD_GENERAL, "Tor is not configured as a relay but you specified"
               " a ServerTransportPlugin line (%s). The ServerTransportPlugin "
               "line will be ignored.",
               escaped(options->ServerTransportPlugin->value));
  }

  for (cl = options->ServerTransportListenAddr; cl; cl = cl->next) {
    /** If get_bindaddr_from_transport_listen_line() fails with
        'transport' being NULL, it means that something went wrong
        while parsing the ServerTransportListenAddr line. */
    char *bindaddr = get_bindaddr_from_transport_listen_line(cl->value, NULL);
    if (!bindaddr)
      REJECT("ServerTransportListenAddr did not parse. See logs for details.");
    tor_free(bindaddr);
  }

  if (options->ServerTransportListenAddr && !options->ServerTransportPlugin) {
    log_notice(LD_GENERAL, "You need at least a single managed-proxy to "
               "specify a transport listen address. The "
               "ServerTransportListenAddr line will be ignored.");
  }

  for (cl = options->ServerTransportOptions; cl; cl = cl->next) {
    /** If get_options_from_transport_options_line() fails with
        'transport' being NULL, it means that something went wrong
        while parsing the ServerTransportOptions line. */
    smartlist_t *options_sl =
      get_options_from_transport_options_line(cl->value, NULL);
    if (!options_sl)
      REJECT("ServerTransportOptions did not parse. See logs for details.");

    SMARTLIST_FOREACH(options_sl, char *, cp, tor_free(cp));
    smartlist_free(options_sl);
  }

  return 0;
}
