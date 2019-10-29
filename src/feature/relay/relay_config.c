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
#define RELAY_CONFIG_PRIVATE
#include "feature/relay/relay_config.h"

#include "lib/encoding/confline.h"

#include "lib/container/smartlist.h"
#include "lib/meminfo/meminfo.h"
#include "lib/osinfo/uname.h"
#include "lib/process/setuid.h"

/* Required for dirinfo_type_t in or_options_t */
#include "core/or/or.h"
#include "app/config/config.h"

#include "core/mainloop/connection.h"
#include "core/or/port_cfg_st.h"

#include "feature/nodelist/nickname.h"

#include "feature/relay/dns.h"
#include "feature/relay/routermode.h"

/* Copied from config.c, we will refactor later in 29211. */
#define REJECT(arg) \
  STMT_BEGIN *msg = tor_strdup(arg); return -1; STMT_END
#if defined(__GNUC__) && __GNUC__ <= 3
#define COMPLAIN(args...) \
  STMT_BEGIN log_warn(LD_CONFIG, args); STMT_END
#else
#define COMPLAIN(args, ...)                                     \
  STMT_BEGIN log_warn(LD_CONFIG, args, ##__VA_ARGS__); STMT_END
#endif /* defined(__GNUC__) && __GNUC__ <= 3 */

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

/**
 * Legacy validation function, which checks that the current OS is usable in
 * relay mode, if options is set to a relay mode.
 *
 * Warns about OSes with potential issues. Always returns 0.
 */
int
options_validate_relay_os(const or_options_t *old_options,
                          or_options_t *options,
                          char **msg)
{
  (void)old_options;

  if (BUG(!options))
    return -1;

  if (BUG(!msg))
    return -1;

  const char *uname = get_uname();

  if (server_mode(options) &&
      (!strcmpstart(uname, "Windows 95") ||
       !strcmpstart(uname, "Windows 98") ||
       !strcmpstart(uname, "Windows Me"))) {
    log_warn(LD_CONFIG, "Tor is running as a server, but you are "
        "running %s; this probably won't work. See "
        "https://www.torproject.org/docs/faq.html#BestOSForRelay "
        "for details.", uname);
  }

  return 0;
}

/**
 * Legacy validation/normalization function for the relay info options.
 * Uses old_options as the previous options.
 *
 * Returns 0 on success, returns -1 and sets *msg to a newly allocated string
 * on error.
 */
int
options_validate_relay_info(const or_options_t *old_options,
                            or_options_t *options,
                            char **msg)
{
  (void)old_options;

  if (BUG(!options))
    return -1;

  if (BUG(!msg))
    return -1;

  if (options->Nickname == NULL) {
    if (server_mode(options)) {
      options->Nickname = tor_strdup(UNNAMED_ROUTER_NICKNAME);
    }
  } else {
    if (!is_legal_nickname(options->Nickname)) {
      tor_asprintf(msg,
          "Nickname '%s', nicknames must be between 1 and 19 characters "
          "inclusive, and must contain only the characters [a-zA-Z0-9].",
          options->Nickname);
      return -1;
    }
  }

  if (server_mode(options) && !options->ContactInfo)
    log_notice(LD_CONFIG, "Your ContactInfo config option is not set. "
        "Please consider setting it, so we can contact you if your server is "
        "misconfigured or something else goes wrong.");

  const char *ContactInfo = options->ContactInfo;
  if (ContactInfo && !string_is_utf8(ContactInfo, strlen(ContactInfo)))
    REJECT("ContactInfo config option must be UTF-8.");

  return 0;
}

/** Parse an authority type from <b>options</b>-\>PublishServerDescriptor
 * and write it to <b>options</b>-\>PublishServerDescriptor_. Treat "1"
 * as "v3" unless BridgeRelay is 1, in which case treat it as "bridge".
 * Treat "0" as "".
 * Return 0 on success or -1 if not a recognized authority type (in which
 * case the value of PublishServerDescriptor_ is undefined). */
static int
compute_publishserverdescriptor(or_options_t *options)
{
  smartlist_t *list = options->PublishServerDescriptor;
  dirinfo_type_t *auth = &options->PublishServerDescriptor_;
  *auth = NO_DIRINFO;
  if (!list) /* empty list, answer is none */
    return 0;
  SMARTLIST_FOREACH_BEGIN(list, const char *, string) {
    if (!strcasecmp(string, "v1"))
      log_warn(LD_CONFIG, "PublishServerDescriptor v1 has no effect, because "
                          "there are no v1 directory authorities anymore.");
    else if (!strcmp(string, "1"))
      if (options->BridgeRelay)
        *auth |= BRIDGE_DIRINFO;
      else
        *auth |= V3_DIRINFO;
    else if (!strcasecmp(string, "v2"))
      log_warn(LD_CONFIG, "PublishServerDescriptor v2 has no effect, because "
                          "there are no v2 directory authorities anymore.");
    else if (!strcasecmp(string, "v3"))
      *auth |= V3_DIRINFO;
    else if (!strcasecmp(string, "bridge"))
      *auth |= BRIDGE_DIRINFO;
    else if (!strcasecmp(string, "hidserv"))
      log_warn(LD_CONFIG,
               "PublishServerDescriptor hidserv is invalid. See "
               "PublishHidServDescriptors.");
    else if (!strcasecmp(string, "") || !strcmp(string, "0"))
      /* no authority */;
    else
      return -1;
  } SMARTLIST_FOREACH_END(string);
  return 0;
}

/**
 * Validate the configured bridge distribution method from a BridgeDistribution
 * config line.
 *
 * The input <b>bd</b>, is a string taken from the BridgeDistribution config
 * line (if present).  If the option wasn't set, return 0 immediately.  The
 * BridgeDistribution option is then validated.  Currently valid, recognised
 * options are:
 *
 * - "none"
 * - "any"
 * - "https"
 * - "email"
 * - "moat"
 * - "hyphae"
 *
 * If the option string is unrecognised, a warning will be logged and 0 is
 * returned.  If the option string contains an invalid character, -1 is
 * returned.
 **/
STATIC int
check_bridge_distribution_setting(const char *bd)
{
  if (bd == NULL)
    return 0;

  const char *RECOGNIZED[] = {
    "none", "any", "https", "email", "moat", "hyphae"
  };
  unsigned i;
  for (i = 0; i < ARRAY_LENGTH(RECOGNIZED); ++i) {
    if (!strcmp(bd, RECOGNIZED[i]))
      return 0;
  }

  const char *cp = bd;
  //  Method = (KeywordChar | "_") +
  while (TOR_ISALNUM(*cp) || *cp == '-' || *cp == '_')
    ++cp;

  if (*cp == 0) {
    log_warn(LD_CONFIG, "Unrecognized BridgeDistribution value %s. I'll "
           "assume you know what you are doing...", escaped(bd));
    return 0; // we reached the end of the string; all is well
  } else {
    return -1; // we found a bad character in the string.
  }
}

/**
 * Legacy validation/normalization function for the bridge relay options.
 * Uses old_options as the previous options.
 *
 * Returns 0 on success, returns -1 and sets *msg to a newly allocated string
 * on error.
 */
int
options_validate_publish_server(const or_options_t *old_options,
                                or_options_t *options,
                                char **msg)
{
  (void)old_options;

  if (BUG(!options))
    return -1;

  if (BUG(!msg))
    return -1;

  if (compute_publishserverdescriptor(options) < 0) {
    tor_asprintf(msg, "Unrecognized value in PublishServerDescriptor");
    return -1;
  }

  if ((options->BridgeRelay
        || options->PublishServerDescriptor_ & BRIDGE_DIRINFO)
      && (options->PublishServerDescriptor_ & V3_DIRINFO)) {
    REJECT("Bridges are not supposed to publish router descriptors to the "
           "directory authorities. Please correct your "
           "PublishServerDescriptor line.");
  }

  if (options->BridgeDistribution) {
    if (!options->BridgeRelay) {
      REJECT("You set BridgeDistribution, but you didn't set BridgeRelay!");
    }
    if (check_bridge_distribution_setting(options->BridgeDistribution) < 0) {
      REJECT("Invalid BridgeDistribution value.");
    }
  }

  if (options->PublishServerDescriptor)
    SMARTLIST_FOREACH(options->PublishServerDescriptor, const char *, pubdes, {
      if (!strcmp(pubdes, "1") || !strcmp(pubdes, "0"))
        if (smartlist_len(options->PublishServerDescriptor) > 1) {
          COMPLAIN("You have passed a list of multiple arguments to the "
                   "PublishServerDescriptor option that includes 0 or 1. "
                   "0 or 1 should only be used as the sole argument. "
                   "This configuration will be rejected in a future release.");
          break;
        }
    });

  return 0;
}

/**
 * Legacy validation/normalization function for the relay padding options.
 * Uses old_options as the previous options.
 *
 * Returns 0 on success, returns -1 and sets *msg to a newly allocated string
 * on error.
 */
int
options_validate_relay_padding(const or_options_t *old_options,
                               or_options_t *options,
                               char **msg)
{
  (void)old_options;

  if (BUG(!options))
    return -1;

  if (BUG(!msg))
    return -1;

  if (server_mode(options) && options->ConnectionPadding != -1) {
    REJECT("Relays must use 'auto' for the ConnectionPadding setting.");
  }

  if (server_mode(options) && options->ReducedConnectionPadding != 0) {
    REJECT("Relays cannot set ReducedConnectionPadding. ");
  }

  if (server_mode(options) && options->CircuitPadding == 0) {
    REJECT("Relays cannot set CircuitPadding to 0. ");
  }

  if (server_mode(options) && options->ReducedCircuitPadding == 1) {
    REJECT("Relays cannot set ReducedCircuitPadding. ");
  }

  return 0;
}

/**
 * Legacy validation/normalization function for the relay bandwidth options.
 * Uses old_options as the previous options.
 *
 * Returns 0 on success, returns -1 and sets *msg to a newly allocated string
 * on error.
 */
int
options_validate_relay_bandwidth(const or_options_t *old_options,
                                 or_options_t *options,
                                 char **msg)
{
  (void)old_options;

  if (BUG(!options))
    return -1;

  if (BUG(!msg))
    return -1;

  if (server_mode(options)) {
    const unsigned required_min_bw =
      public_server_mode(options) ?
       RELAY_REQUIRED_MIN_BANDWIDTH : BRIDGE_REQUIRED_MIN_BANDWIDTH;
    const char * const optbridge =
      public_server_mode(options) ? "" : "bridge ";
    if (options->BandwidthRate < required_min_bw) {
      tor_asprintf(msg,
                       "BandwidthRate is set to %d bytes/second. "
                       "For %sservers, it must be at least %u.",
                       (int)options->BandwidthRate, optbridge,
                       required_min_bw);
      return -1;
    } else if (options->MaxAdvertisedBandwidth <
               required_min_bw/2) {
      tor_asprintf(msg,
                       "MaxAdvertisedBandwidth is set to %d bytes/second. "
                       "For %sservers, it must be at least %u.",
                       (int)options->MaxAdvertisedBandwidth, optbridge,
                       required_min_bw/2);
      return -1;
    }
    if (options->RelayBandwidthRate &&
      options->RelayBandwidthRate < required_min_bw) {
      tor_asprintf(msg,
                       "RelayBandwidthRate is set to %d bytes/second. "
                       "For %sservers, it must be at least %u.",
                       (int)options->RelayBandwidthRate, optbridge,
                       required_min_bw);
      return -1;
    }
  }

  return 0;
}

/** Verify whether lst is a list of strings containing valid-looking
 * comma-separated nicknames, or NULL. Will normalise <b>lst</b> to prefix '$'
 * to any nickname or fingerprint that needs it. Also splits comma-separated
 * list elements into multiple elements. Return 0 on success.
 * Warn and return -1 on failure.
 */
static int
normalize_nickname_list(config_line_t **normalized_out,
                        const config_line_t *lst, const char *name,
                        char **msg)
{
  if (!lst)
    return 0;

  config_line_t *new_nicknames = NULL;
  config_line_t **new_nicknames_next = &new_nicknames;

  const config_line_t *cl;
  for (cl = lst; cl; cl = cl->next) {
    const char *line = cl->value;
    if (!line)
      continue;

    int valid_line = 1;
    smartlist_t *sl = smartlist_new();
    smartlist_split_string(sl, line, ",",
      SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK|SPLIT_STRIP_SPACE, 0);
    SMARTLIST_FOREACH_BEGIN(sl, char *, s)
    {
      char *normalized = NULL;
      if (!is_legal_nickname_or_hexdigest(s)) {
        // check if first char is dollar
        if (s[0] != '$') {
          // Try again but with a dollar symbol prepended
          char *prepended;
          tor_asprintf(&prepended, "$%s", s);

          if (is_legal_nickname_or_hexdigest(prepended)) {
            // The nickname is valid when it's prepended, set it as the
            // normalized version
            normalized = prepended;
          } else {
            // Still not valid, free and fallback to error message
            tor_free(prepended);
          }
        }

        if (!normalized) {
          tor_asprintf(msg, "Invalid nickname '%s' in %s line", s, name);
          valid_line = 0;
          break;
        }
      } else {
        normalized = tor_strdup(s);
      }

      config_line_t *next = tor_malloc_zero(sizeof(*next));
      next->key = tor_strdup(cl->key);
      next->value = normalized;
      next->next = NULL;

      *new_nicknames_next = next;
      new_nicknames_next = &next->next;
    } SMARTLIST_FOREACH_END(s);

    SMARTLIST_FOREACH(sl, char *, s, tor_free(s));
    smartlist_free(sl);

    if (!valid_line) {
      config_free_lines(new_nicknames);
      return -1;
    }
  }

  *normalized_out = new_nicknames;

  return 0;
}

#define ONE_MEGABYTE (UINT64_C(1) << 20)

/* If we have less than 300 MB suggest disabling dircache */
#define DIRCACHE_MIN_MEM_MB 300
#define DIRCACHE_MIN_MEM_BYTES (DIRCACHE_MIN_MEM_MB*ONE_MEGABYTE)
#define STRINGIFY(val) #val

/** Create a warning message for emitting if we are a dircache but may not have
 * enough system memory, or if we are not a dircache but probably should be.
 * Return -1 when a message is returned in *msg*, else return 0. */
STATIC int
have_enough_mem_for_dircache(const or_options_t *options, size_t total_mem,
                             char **msg)
{
  *msg = NULL;
  /* XXX We should possibly be looking at MaxMemInQueues here
   * unconditionally.  Or we should believe total_mem unconditionally. */
  if (total_mem == 0) {
    if (get_total_system_memory(&total_mem) < 0) {
      total_mem = options->MaxMemInQueues >= SIZE_MAX ?
        SIZE_MAX : (size_t)options->MaxMemInQueues;
    }
  }
  if (options->DirCache) {
    if (total_mem < DIRCACHE_MIN_MEM_BYTES) {
      if (options->BridgeRelay) {
        tor_asprintf(msg, "Running a Bridge with less than %d MB of memory "
                       "is not recommended.", DIRCACHE_MIN_MEM_MB);
      } else {
        tor_asprintf(msg, "Being a directory cache (default) with less than "
                       "%d MB of memory is not recommended and may consume "
                       "most of the available resources. Consider disabling "
                       "this functionality by setting the DirCache option "
                       "to 0.", DIRCACHE_MIN_MEM_MB);
      }
    }
  } else {
    if (total_mem >= DIRCACHE_MIN_MEM_BYTES) {
      *msg = tor_strdup("DirCache is disabled and we are configured as a "
               "relay. We will not become a Guard.");
    }
  }
  return *msg == NULL ? 0 : -1;
}
#undef STRINGIFY

/**
 * Legacy validation/normalization function for the relay mode options.
 * Uses old_options as the previous options.
 *
 * Returns 0 on success, returns -1 and sets *msg to a newly allocated string
 * on error.
 */
int
options_validate_relay_mode(const or_options_t *old_options,
                            or_options_t *options,
                            char **msg)
{
  (void)old_options;

  if (BUG(!options))
    return -1;

  if (BUG(!msg))
    return -1;

  if (options->BridgeRelay && options->DirPort_set) {
    log_warn(LD_CONFIG, "Can't set a DirPort on a bridge relay; disabling "
             "DirPort");
    config_free_lines(options->DirPort_lines);
    options->DirPort_lines = NULL;
    options->DirPort_set = 0;
  }

  if (options->DirPort_set && !options->DirCache) {
    REJECT("DirPort configured but DirCache disabled. DirPort requires "
           "DirCache.");
  }

  if (options->BridgeRelay && !options->DirCache) {
    REJECT("We're a bridge but DirCache is disabled. BridgeRelay requires "
           "DirCache.");
  }

  if (options->BridgeRelay == 1 && ! options->ORPort_set)
    REJECT("BridgeRelay is 1, ORPort is not set. This is an invalid "
           "combination.");

  if (server_mode(options)) {
    char *dircache_msg = NULL;
    if (have_enough_mem_for_dircache(options, 0, &dircache_msg)) {
      log_warn(LD_CONFIG, "%s", dircache_msg);
      tor_free(dircache_msg);
    }
  }

  if (options->MyFamily_lines && options->BridgeRelay) {
    log_warn(LD_CONFIG, "Listing a family for a bridge relay is not "
             "supported: it can reveal bridge fingerprints to censors. "
             "You should also make sure you aren't listing this bridge's "
             "fingerprint in any other MyFamily.");
  }
  if (options->MyFamily_lines && !options->ContactInfo) {
    log_warn(LD_CONFIG, "MyFamily is set but ContactInfo is not configured. "
             "ContactInfo should always be set when MyFamily option is too.");
  }
  if (normalize_nickname_list(&options->MyFamily,
                              options->MyFamily_lines, "MyFamily", msg))
    return -1;

  return 0;
}
