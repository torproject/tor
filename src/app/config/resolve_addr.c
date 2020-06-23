/* Copyright (c) 2020, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file resolve_addr.c
 * \brief Implement resolving address functions
 **/

#define RESOLVE_ADDR_PRIVATE

#include "app/config/config.h"
#include "app/config/resolve_addr.h"

#include "core/mainloop/mainloop.h"

#include "feature/control/control_events.h"

#include "lib/encoding/confline.h"
#include "lib/net/gethostname.h"
#include "lib/net/resolve.h"

/** Maximum "Address" statement allowed in our configuration. */
#define MAX_CONFIG_ADDRESS 2

/** Errors use when finding our IP address. Some are transient and some are
 * persistent, just attach semantic to the values. They are all negative so
 * one can do a catch all. */

#define ERR_FAIL_RESOLVE        -1 /* Hostname resolution failed. */
#define ERR_GET_HOSTNAME        -2 /* Unable to get local hostname. */
#define ERR_NO_OPT_ADDRESS      -3 /* No Address in config. */
#define ERR_TOO_MANY_ADDRESS    -4 /* Too many Address for one family. */
#define ERR_GET_INTERFACE       -5 /* Unable to query network interface. */
#define ERR_UNUSABLE_ADDRESS    -6 /* Unusable address. It is internal. */
#define ERR_DEFAULT_DIRAUTH     -7 /* Using default authorities. */
#define ERR_ADDRESS_IS_INTERNAL -8 /* IP is internal. */

/** Ease our life. Arrays containing state per address family. These are to
 * add semantic to the code so we know what is accessed. */
#define IDX_IPV4 0 /* Index to AF_INET. */
#define IDX_IPV6 1 /* Index to AF_INET6. */
#define IDX_SIZE 2 /* How many indexes do we have. */

/** Last resolved addresses. */
static tor_addr_t last_resolved_addrs[IDX_SIZE];

/** Copy the last resolved address of family into addr_out.
 *
 * If not last resolved address existed, the addr_out is a null address (use
 * tor_addr_is_null()). */
void
resolved_addr_get_last(int family, tor_addr_t *addr_out)
{
  tor_addr_copy(addr_out, &last_resolved_addrs[family]);
}

/** Reset the last resolved address of family.
 *
 * This makes it null address. */
void
resolved_addr_reset_last(int family)
{
  tor_addr_make_null(&last_resolved_addrs[family], family);
}

/** @brief Return true iff the given IP address can be used as a valid
 *         external resolved address.
 *
 * Two tests are done in this function:
 *    1) If the address if NOT internal, it can be used.
 *    2) If the address is internal and we have custom directory authorities
 *       configured then it can they be used. Important for testing networks.
 *
 * @param addr The IP address to validate.
 * @param options Global configuration options.
 * @param warn_severity Log level that should be used on error.
 * @param explicit_ip Was the IP address explicitly given.
 *
 * @return Return 0 if it can be used. Return error code ERR_* found at the
 *         top of the file.
 */
static int
address_can_be_used(const tor_addr_t *addr, const or_options_t *options,
                    int warn_severity, const bool explicit_ip)
{
  tor_assert(addr);

  /* Public address, this is fine. */
  if (!tor_addr_is_internal(addr, 0)) {
    goto allow;
  }

  /* We have a private IP address. It is allowed only if we set custom
   * directory authorities. */
  if (using_default_dir_authorities(options)) {
    log_fn(warn_severity, LD_CONFIG,
           "Address '%s' is a private IP address. Tor relays that use "
           "the default DirAuthorities must have public IP addresses.",
           fmt_addr(addr));
    return ERR_DEFAULT_DIRAUTH;
  }

  if (!explicit_ip) {
    /* Even with custom directory authorities, only an explicit internal
     * address is accepted. */
    log_fn(warn_severity, LD_CONFIG,
           "Address %s was resolved and thus not explicitly "
           "set. Even if DirAuthorities are custom, this is "
           "not allowed.", fmt_addr(addr));
    return ERR_ADDRESS_IS_INTERNAL;
  }

 allow:
  return 0;
}

/** @brief Get IP address from the given config line and for a specific address
 *         family.
 *
 * This can fail is more than two Address statement are found for the same
 * address family. It also fails if no statement is found.
 *
 * On failure, no out parameters should be used or considered valid.
 *
 * @param options Global configuration options.
 * @param warn_severity Log level that should be used on error.
 * @param family IP address family. Only AF_INET and AF_INET6 are supported.
 * @param method_out OUT: String denoting by which method the address was
 *                   found. This is described in the control-spec.txt as
 *                   actions for "STATUS_SERVER".
 * @param hostname_out OUT: String containing the hostname gotten from the
 *                     Address value if any.
 * @param addr_out OUT: Tor address of the address found in the cline or
 *                 resolved from the cline.
 *
 * @return Return 0 on success that is an address has been found or resolved
 *         successfully. Return error code ERR_* found at the top of the file.
 */
static int
get_address_from_config(const or_options_t *options, int warn_severity,
                        int family, const char **method_out,
                        char **hostname_out, tor_addr_t *addr_out)
{
  bool explicit_ip = false;
  int num_valid_addr = 0;

  tor_assert(options);
  tor_assert(addr_out);
  tor_assert(method_out);
  tor_assert(hostname_out);

  log_debug(LD_CONFIG, "Attempting to get address from configuration");

  if (!options->Address) {
    log_info(LD_CONFIG, "No Address option found in configuration.");
    return ERR_NO_OPT_ADDRESS;
  }

  for (const config_line_t *cfg = options->Address; cfg != NULL;
       cfg = cfg->next) {
    int af;
    tor_addr_t addr;

    af = tor_addr_parse(&addr, cfg->value);
    if (af == family) {
      tor_addr_copy(addr_out, &addr);
      *method_out = "CONFIGURED";
      explicit_ip = true;
      num_valid_addr++;
      continue;
    }

    /* Not an IP address. Considering this value a hostname and attempting to
     * do a DNS lookup. */
    if (!tor_addr_lookup(cfg->value, family, &addr)) {
      tor_addr_copy(addr_out, &addr);
      *method_out = "RESOLVED";
      *hostname_out = tor_strdup(cfg->value);
      explicit_ip = false;
      num_valid_addr++;
      continue;
    } else {
      /* If we have hostname we are unable to resolve, it is an persistent
       * error and thus we stop right away. */
      log_fn(warn_severity, LD_CONFIG,
             "Could not resolve local Address '%s'. Failing.", cfg->value);
      return ERR_FAIL_RESOLVE;
    }
  }

  if (!num_valid_addr) {
    log_fn(warn_severity, LD_CONFIG,
           "No Address option found for family %s in configuration.",
           fmt_af_family(family));
    return ERR_NO_OPT_ADDRESS;
  }

  if (num_valid_addr >= MAX_CONFIG_ADDRESS) {
    log_fn(warn_severity, LD_CONFIG,
           "Found %d Address statement of address family %s. "
           "Only one is allowed.", num_valid_addr, fmt_af_family(family));
    return ERR_TOO_MANY_ADDRESS;
  }

  /* Great, we found an address. */
  return address_can_be_used(addr_out, options, warn_severity, explicit_ip);
}

/** @brief Get IP address from the local hostname by calling gethostbyname()
 *         and doing a DNS resolution on the hostname.
 *
 * On failure, no out parameters should be used or considered valid.
 *
 * @param options Global configuration options.
 * @param warn_severity Log level that should be used on error.
 * @param family IP address family. Only AF_INET and AF_INET6 are supported.
 * @param method_out OUT: String denoting by which method the address was
 *                   found. This is described in the control-spec.txt as
 *                   actions for "STATUS_SERVER".
 * @param hostname_out OUT: String containing the local hostname.
 * @param addr_out OUT: Tor address resolved from the local hostname.
 *
 * @return Return 0 on success that is an address has been found and resolved
 *         successfully. Return error code ERR_* found at the top of the file.
 */
static int
get_address_from_hostname(const or_options_t *options, int warn_severity,
                          int family, const char **method_out,
                          char **hostname_out, tor_addr_t *addr_out)
{
  int ret;
  char hostname[256];

  tor_assert(addr_out);
  tor_assert(method_out);

  log_debug(LD_CONFIG, "Attempting to get address from local hostname");

  if (tor_gethostname(hostname, sizeof(hostname)) < 0) {
    log_fn(warn_severity, LD_NET, "Error obtaining local hostname");
    return ERR_GET_HOSTNAME;
  }
  if (tor_addr_lookup(hostname, family, addr_out)) {
    log_fn(warn_severity, LD_NET,
           "Could not resolve local hostname '%s'. Failing.", hostname);
    return ERR_FAIL_RESOLVE;
  }

  ret = address_can_be_used(addr_out, options, warn_severity, false);
  if (ret < 0) {
    return ret;
  }

  /* addr_out contains the address of the local hostname. */
  *method_out = "GETHOSTNAME";
  *hostname_out = tor_strdup(hostname);

  return 0;
}

/** @brief Get IP address from a network interface.
 *
 * On failure, no out parameters should be used or considered valid.
 *
 * @param options Global configuration options.
 * @param warn_severity Log level that should be used on error.
 * @param family IP address family. Only AF_INET and AF_INET6 are supported.
 * @param method_out OUT: Always "INTERFACE" on success which is detailed in
 *                   the control-spec.txt as actions for "STATUS_SERVER".
 * @param addr_out OUT: Tor address found attached to the interface.
 *
 * @return Return 0 on success that is an address has been found. Return
 *         error code ERR_* found at the top of the file.
 */
static int
get_address_from_interface(const or_options_t *options, int warn_severity,
                           int family, const char **method_out,
                           tor_addr_t *addr_out)
{
  int ret;

  tor_assert(method_out);
  tor_assert(addr_out);

  log_debug(LD_CONFIG, "Attempting to get address from network interface");

  if (get_interface_address6(warn_severity, family, addr_out) < 0) {
    log_fn(warn_severity, LD_CONFIG,
           "Could not get local interface IP address.");
    return ERR_GET_INTERFACE;
  }

  ret = address_can_be_used(addr_out, options, warn_severity, false);
  if (ret < 0) {
    return ret;
  }

  *method_out = "INTERFACE";

  return 0;
}

/** @brief Update the last resolved address cache using the given address.
 *
 * A log notice is emitted if the given address has changed from before. Not
 * emitted on first resolve.
 *
 * Control port event "STATUS_SERVER" is emitted with the new information if
 * it has changed.
 *
 * Finally, tor is notified that the IP address has changed.
 *
 * @param addr IP address to update the cache with.
 * @param method_used By which method did we resolved it (for logging and
 *                    control port).
 * @param hostname_used Which hostname was used. If none were used, it is an
 *                      empty string. (for logging and control port).
 */
static void
update_resolved_cache(const tor_addr_t *addr, const char *method_used,
                      const char *hostname_used)
{
  /** Have we done a first resolve. This is used to control logging. */
  static bool have_resolved_once[IDX_SIZE] = { false, false };
  bool done_one_resolve;
  bool have_hostname = false;
  tor_addr_t *last_resolved;

  tor_assert(addr);
  tor_assert(method_used);
  tor_assert(hostname_used);

  /* Do we have an hostname. */
  have_hostname = strlen(hostname_used) > 0;

  switch (tor_addr_family(addr)) {
  case AF_INET:
    done_one_resolve = have_resolved_once[IDX_IPV4];
    last_resolved = &last_resolved_addrs[IDX_IPV4];
    break;
  case AF_INET6:
    done_one_resolve = have_resolved_once[IDX_IPV6];
    last_resolved = &last_resolved_addrs[IDX_IPV6];
    break;
  default:
    tor_assert_nonfatal_unreached();
    return;
  }

  /* Same address last resolved. Ignore. */
  if (tor_addr_eq(last_resolved, addr)) {
    return;
  }

  /* Don't log notice if this is the first resolve we do. */
  if (!done_one_resolve) {
    /* Leave this as a notice, regardless of the requested severity,
     * at least until dynamic IP address support becomes bulletproof. */
    log_notice(LD_NET,
               "Your IP address seems to have changed to %s "
               "(METHOD=%s%s%s). Updating.",
               fmt_addr(addr), method_used,
               have_hostname ? " HOSTNAME=" : "",
               have_hostname ? hostname_used : "");
    ip_address_changed(0);
    done_one_resolve = true;
  }

  /* Notify control port. */
  control_event_server_status(LOG_NOTICE,
                              "EXTERNAL_ADDRESS ADDRESS=%s METHOD=%s%s%s",
                              fmt_addr(addr), method_used,
                              have_hostname ? " HOSTNAME=" : "",
                              have_hostname ? hostname_used : "");
  /* Copy address to cache. */
  tor_addr_copy(last_resolved, addr);
}

/** @brief Attempt to find our IP address that can be used as our external
 *         reachable address.
 *
 *  The following describe the algorithm to find an address. Each have
 *  specific conditions so read carefully.
 *
 *  On success, true is returned and depending on how the address was found,
 *  the out parameters can have different values.
 *
 *  On error, false is returned and all out parameters are untouched.
 *
 *  1. Look at the configuration Address option.

 *     If Address is a public address, True is returned and addr_out is set
 *     with it, the method_out is set to "CONFIGURED" and hostname_out is set
 *     to NULL.
 *
 *     If Address is an internal address but NO custom authorities are used,
 *     an error is returned.
 *
 *     If Address is a hostname, that is it can't be converted to an address,
 *     it is resolved. On success, addr_out is set with the address,
 *     method_out is set to "RESOLVED" and hostname_out is set to the resolved
 *     hostname. On failure to resolve, an error is returned.
 *
 *     If no given Address, fallback to the local hostname (see section 2).
 *
 *  2. Look at the local hostname.
 *
 *     If the local hostname resolves to a non internal address, addr_out is
 *     set with it, method_out is set to "GETHOSTNAME" and hostname_out is set
 *     to the resolved hostname.
 *
 *     If a local hostname can NOT be found, an error is returned.
 *
 *     If the local hostname resolves to an internal address, an error is
 *     returned.
 *
 *     If the local hostname can NOT be resolved, fallback to the network
 *     interface (see section 3).
 *
 *  3. Look at the network interface.
 *
 *     Attempt to find the first public usable address from the list of
 *     network interface returned by the OS.
 *
 *     On failure, an error is returned. This error indicates that all
 *     attempts have failed and thus the address for the given family can not
 *     be found.
 *
 *     On success, addr_out is set with it, method_out is set to "INTERFACE"
 *     and hostname_out is set to NULL.
 *
 * @param options Global configuration options.
 * @param family IP address family. Only AF_INET and AF_INET6 are supported.
 * @param warn_severity Logging level.
 * @param addr_out OUT: Set with the IP address found if any.
 * @param method_out OUT: (optional) String denoting by which method the
 *                   address was found. This is described in the
 *                   control-spec.txt as actions for "STATUS_SERVER".
 * @param hostname_out OUT: String containing the hostname if any was used.
 *                     Only be set for "RESOLVED" and "GETHOSTNAME" methods.
 *                     Else it is set to NULL.
 *
 * @return True if the address was found for the given family. False if not or
 *         on errors.
 */
bool
find_my_address(const or_options_t *options, int family, int warn_severity,
                tor_addr_t *addr_out, const char **method_out,
                char **hostname_out)
{
  int ret;
  const char *method_used;
  char *hostname_used = tor_strdup("");
  tor_addr_t my_addr;

  tor_assert(options);
  tor_assert(addr_out);

  /*
   * Step 1: Discover address by attempting 3 different methods consecutively.
   */

  /* Attempt #1: Get address from configuration. */
  ret = get_address_from_config(options, warn_severity, family, &method_used,
                                &hostname_used, &my_addr);
  if (ret == 0) {
    log_fn(warn_severity, LD_CONFIG, "Address found in configuration: %s",
           fmt_addr(&my_addr));
  } else {
    /* Unable to resolve an Address statement is a failure. Also, using
     * default dirauth error means that the configured address is internal
     * which is only accepted if custom authorities are used. */
    if (ret == ERR_FAIL_RESOLVE || ret == ERR_DEFAULT_DIRAUTH) {
      return false;
    }

    /* Attempt #2: Get local hostname and resolve it. */
    ret = get_address_from_hostname(options, warn_severity, family,
                                    &method_used, &hostname_used, &my_addr);
    if (ret == 0) {
      log_fn(warn_severity, LD_CONFIG, "Address found from local hostname: "
             "%s", fmt_addr(&my_addr));
    } else if (ret < 0) {
      /* Unable to get the hostname results in a failure. If the address is
       * internal, we stop right away. */
      if (ret == ERR_GET_HOSTNAME || ret == ERR_ADDRESS_IS_INTERNAL) {
        return false;
      }

      /* Attempt #3: Get address from interface. */
      ret = get_address_from_interface(options, warn_severity, family,
                                       &method_used, &my_addr);
      if (ret == 0) {
        log_fn(warn_severity, LD_CONFIG, "Address found from interface: %s",
               fmt_addr(&my_addr));
      } else {
        /* We've exhausted our attempts. Failure. */
        log_fn(warn_severity, LD_CONFIG, "Unable to find our IP address.");
        return false;
      }
    }
  }
  tor_assert(method_used);

  /* From here, my_addr is a valid IP address of "family" and can be used as
   * our external IP address. */

  /*
   * Step 2: Update last resolved address cache and inform the control port.
   */
  update_resolved_cache(&my_addr, method_used, hostname_used);

  if (method_out) {
    *method_out = method_used;
  }
  if (hostname_out) {
    *hostname_out = NULL;
    if (strlen(hostname_used) > 0) {
      *hostname_out = hostname_used;
    }
  } else {
    tor_free(hostname_used);
  }

  tor_addr_copy(addr_out, &my_addr);
  return true;
}

/** Return true iff <b>addr</b> is judged to be on the same network as us, or
 * on a private network.
 */
MOCK_IMPL(bool,
resolved_addr_is_local, (const tor_addr_t *addr))
{
  const int family = tor_addr_family(addr);
  const tor_addr_t *last_resolved_addr = &last_resolved_addrs[family];

  /* Internal address is always local. */
  if (tor_addr_is_internal(addr, 0)) {
    return true;
  }

  /* Address is not local if we don't enforce subnet distinction. */
  if (get_options()->EnforceDistinctSubnets == 0) {
    return false;
  }

  switch (family) {
  case AF_INET:
    /* XXX: Why is this /24 and not /16 which the rest of tor does? Unknown
     * reasons at the moment highlighted in ticket #40009. Because of that, we
     * can't use addrs_in_same_network_family(). */

    /* It's possible that this next check will hit before the first time
     * find_my_address actually succeeds. For clients, it is likely that
     * find_my_address will never be called at all. In those cases,
     * last_resolved_addr_v4 will be 0, and so checking to see whether ip is
     * on the same /24 as last_resolved_addrs[AF_INET] will be the same as
     * checking whether it was on net 0, which is already done by
     * tor_addr_is_internal. */
    return tor_addr_compare_masked(addr, last_resolved_addr, 24,
                                   CMP_SEMANTIC) == 0;
  case AF_INET6:
    /* Look at the /32 like addrs_in_same_network_family() does. */
    return tor_addr_compare_masked(addr, last_resolved_addr, 32,
                                   CMP_SEMANTIC) == 0;
    break;
  default:
    /* Unknown address type so not local. */
    return false;
  }
}
