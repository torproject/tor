/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2019, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * @file relay_config.c
 * @brief Code to interpret the user's configuration of Tor's relay module.
 **/

#include "orconfig.h"
#include "feature/relay/relay_config.h"

#include "lib/encoding/confline.h"
#include "lib/confmgt/confmgt.h"

#include "lib/container/smartlist.h"
#include "lib/process/setuid.h"

/* Required for dirinfo_type_t in or_options_t */
#include "core/or/or.h"
#include "app/config/config.h"

#include "core/mainloop/connection.h"
#include "core/or/port_cfg_st.h"

#include "feature/relay/dns.h"
#include "feature/relay/ext_orport.h"
#include "feature/relay/routermode.h"

/** Given a list of <b>port_cfg_t</b> in <b>ports</b>, check them for internal
 * consistency and warn as appropriate.  On Unix-based OSes, set
 * *<b>n_low_ports_out</b> to the number of sub-1024 ports we will be
 * binding, and warn if we may be unable to re-bind after hibernation. */
static int
check_server_ports(const smartlist_t *ports,
                   const or_options_t *options,
                   int *n_low_ports_out)
{
  if (BUG(!ports))
    return -1;

  if (BUG(!options))
    return -1;

  if (BUG(!n_low_ports_out))
    return -1;

  int n_orport_advertised = 0;
  int n_orport_advertised_ipv4 = 0;
  int n_orport_listeners = 0;
  int n_dirport_advertised = 0;
  int n_dirport_listeners = 0;
  int n_low_port = 0;
  int r = 0;

  SMARTLIST_FOREACH_BEGIN(ports, const port_cfg_t *, port) {
    if (port->type == CONN_TYPE_DIR_LISTENER) {
      if (! port->server_cfg.no_advertise)
        ++n_dirport_advertised;
      if (! port->server_cfg.no_listen)
        ++n_dirport_listeners;
    } else if (port->type == CONN_TYPE_OR_LISTENER) {
      if (! port->server_cfg.no_advertise) {
        ++n_orport_advertised;
        if (port_binds_ipv4(port))
          ++n_orport_advertised_ipv4;
      }
      if (! port->server_cfg.no_listen)
        ++n_orport_listeners;
    } else {
      continue;
    }
#ifndef _WIN32
    if (!port->server_cfg.no_listen && port->port < 1024)
      ++n_low_port;
#endif
  } SMARTLIST_FOREACH_END(port);

  if (n_orport_advertised && !n_orport_listeners) {
    log_warn(LD_CONFIG, "We are advertising an ORPort, but not actually "
             "listening on one.");
    r = -1;
  }
  if (n_orport_listeners && !n_orport_advertised) {
    log_warn(LD_CONFIG, "We are listening on an ORPort, but not advertising "
             "any ORPorts. This will keep us from building a %s "
             "descriptor, and make us impossible to use.",
             options->BridgeRelay ? "bridge" : "router");
    r = -1;
  }
  if (n_dirport_advertised && !n_dirport_listeners) {
    log_warn(LD_CONFIG, "We are advertising a DirPort, but not actually "
             "listening on one.");
    r = -1;
  }
  if (n_dirport_advertised > 1) {
    log_warn(LD_CONFIG, "Can't advertise more than one DirPort.");
    r = -1;
  }
  if (n_orport_advertised && !n_orport_advertised_ipv4 &&
      !options->BridgeRelay) {
    log_warn(LD_CONFIG, "Configured public relay to listen only on an IPv6 "
             "address. Tor needs to listen on an IPv4 address too.");
    r = -1;
  }

  if (n_low_port && options->AccountingMax &&
      (!have_capability_support() || options->KeepBindCapabilities == 0)) {
    const char *extra = "";
    if (options->KeepBindCapabilities == 0 && have_capability_support())
      extra = ", and you have disabled KeepBindCapabilities.";
    log_warn(LD_CONFIG,
          "You have set AccountingMax to use hibernation. You have also "
          "chosen a low DirPort or OrPort%s."
          "This combination can make Tor stop "
          "working when it tries to re-attach the port after a period of "
          "hibernation. Please choose a different port or turn off "
          "hibernation unless you know this combination will work on your "
          "platform.", extra);
  }

  if (n_low_ports_out)
    *n_low_ports_out = n_low_port;

  return r;
}

/** Parse all relay ports from <b>options</b>. On success, add parsed ports to
 * <b>ports</b>, and return 0.  On failure, set *<b>msg</b> to a description
 * of the problem and return -1.
 **/
int
parse_ports_relay(or_options_t *options,
                  char **msg,
                  smartlist_t *ports_out,
                  int *have_low_ports_out)
{
  int retval = -1;
  smartlist_t *ports = smartlist_new();

  if (BUG(!options))
    goto err;

  if (BUG(!msg))
    goto err;

  if (BUG(!ports_out))
    goto err;

  if (BUG(!have_low_ports_out))
    goto err;

  if (! options->ClientOnly) {
    if (parse_port_config(ports,
                          options->ORPort_lines,
                          "OR", CONN_TYPE_OR_LISTENER,
                          "0.0.0.0", 0,
                          CL_PORT_SERVER_OPTIONS) < 0) {
      *msg = tor_strdup("Invalid ORPort configuration");
      goto err;
    }
    if (parse_port_config(ports,
                          options->ExtORPort_lines,
                          "ExtOR", CONN_TYPE_EXT_OR_LISTENER,
                          "127.0.0.1", 0,
                          CL_PORT_SERVER_OPTIONS|CL_PORT_WARN_NONLOCAL) < 0) {
      *msg = tor_strdup("Invalid ExtORPort configuration");
      goto err;
    }
    if (parse_port_config(ports,
                          options->DirPort_lines,
                          "Dir", CONN_TYPE_DIR_LISTENER,
                          "0.0.0.0", 0,
                          CL_PORT_SERVER_OPTIONS) < 0) {
      *msg = tor_strdup("Invalid DirPort configuration");
      goto err;
    }
  }

  int n_low_ports = 0;
  if (check_server_ports(ports, options, &n_low_ports) < 0) {
    *msg = tor_strdup("Misconfigured server ports");
    goto err;
  }
  if (*have_low_ports_out < 0)
    *have_low_ports_out = (n_low_ports > 0);

  smartlist_add_all(ports_out, ports);
  smartlist_free(ports);
  ports = NULL;
  retval = 0;

 err:
  if (ports) {
    SMARTLIST_FOREACH(ports, port_cfg_t *, p, port_cfg_free(p));
    smartlist_free(ports);
  }
  return retval;
}

/** Update the relay *Port_set values in <b>options</b> from <b>ports</b>. */
void
update_port_set_relay(or_options_t *options,
                      const smartlist_t *ports)
{
  if (BUG(!options))
    return;

  if (BUG(!ports))
    return;

  /* Update the relay *Port_set options.  The !! here is to force a boolean
   * out of an integer. */
  options->ORPort_set =
    !! count_real_listeners(ports, CONN_TYPE_OR_LISTENER, 0);
  options->DirPort_set =
    !! count_real_listeners(ports, CONN_TYPE_DIR_LISTENER, 0);
  options->ExtORPort_set =
    !! count_real_listeners(ports, CONN_TYPE_EXT_OR_LISTENER, 0);
}
