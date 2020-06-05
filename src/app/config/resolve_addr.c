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

#include "lib/net/gethostname.h"
#include "lib/net/resolve.h"

/** Last value actually set by resolve_my_address. */
static uint32_t last_resolved_addr = 0;

/** Accessor for last_resolved_addr from outside this file. */
uint32_t
get_last_resolved_addr(void)
{
  return last_resolved_addr;
}

/** Reset last_resolved_addr from outside this file. */
void
reset_last_resolved_addr(void)
{
  last_resolved_addr = 0;
}

/**
 * Attempt getting our non-local (as judged by tor_addr_is_internal()
 * function) IP address using following techniques, listed in
 * order from best (most desirable, try first) to worst (least
 * desirable, try if everything else fails).
 *
 * First, attempt using <b>options-\>Address</b> to get our
 * non-local IP address.
 *
 * If <b>options-\>Address</b> represents a non-local IP address,
 * consider it ours.
 *
 * If <b>options-\>Address</b> is a DNS name that resolves to
 * a non-local IP address, consider this IP address ours.
 *
 * If <b>options-\>Address</b> is NULL, fall back to getting local
 * hostname and using it in above-described ways to try and
 * get our IP address.
 *
 * In case local hostname cannot be resolved to a non-local IP
 * address, try getting an IP address of network interface
 * in hopes it will be non-local one.
 *
 * Fail if one or more of the following is true:
 *   - DNS name in <b>options-\>Address</b> cannot be resolved.
 *   - <b>options-\>Address</b> is a local host address.
 *   - Attempt at getting local hostname fails.
 *   - Attempt at getting network interface address fails.
 *
 * Return 0 if all is well, or -1 if we can't find a suitable
 * public IP address.
 *
 * If we are returning 0:
 *   - Put our public IP address (in host order) into *<b>addr_out</b>.
 *   - If <b>method_out</b> is non-NULL, set *<b>method_out</b> to a static
 *     string describing how we arrived at our answer.
 *      - "CONFIGURED" - parsed from IP address string in
 *        <b>options-\>Address</b>
 *      - "RESOLVED" - resolved from DNS name in <b>options-\>Address</b>
 *      - "GETHOSTNAME" - resolved from a local hostname.
 *      - "INTERFACE" - retrieved from a network interface.
 *   - If <b>hostname_out</b> is non-NULL, and we resolved a hostname to
 *     get our address, set *<b>hostname_out</b> to a newly allocated string
 *     holding that hostname. (If we didn't get our address by resolving a
 *     hostname, set *<b>hostname_out</b> to NULL.)
 *
 * XXXX ipv6
 */
int
resolve_my_address(int warn_severity, const or_options_t *options,
                   uint32_t *addr_out,
                   const char **method_out, char **hostname_out)
{
  struct in_addr in;
  uint32_t addr; /* host order */
  char hostname[256];
  const char *method_used;
  const char *hostname_used;
  int explicit_ip=1;
  int explicit_hostname=1;
  int from_interface=0;
  char *addr_string = NULL;
  const char *address = options->Address;
  int notice_severity = warn_severity <= LOG_NOTICE ?
    LOG_NOTICE : warn_severity;

  tor_addr_t myaddr;
  tor_assert(addr_out);

  /*
   * Step one: Fill in 'hostname' to be our best guess.
   */

  if (address && *address) {
    strlcpy(hostname, address, sizeof(hostname));
    log_debug(LD_CONFIG, "Trying configured Address '%s' as local hostname",
              hostname);
  } else { /* then we need to guess our address */
    explicit_ip = 0; /* it's implicit */
    explicit_hostname = 0; /* it's implicit */

    if (tor_gethostname(hostname, sizeof(hostname)) < 0) {
      log_fn(warn_severity, LD_NET,"Error obtaining local hostname");
      return -1;
    }
    log_debug(LD_CONFIG, "Guessed local host name as '%s'", hostname);
  }

  /*
   * Step two: Now that we know 'hostname', parse it or resolve it. If
   * it doesn't parse or resolve, look at the interface address. Set 'addr'
   * to be our (host-order) 32-bit answer.
   */

  if (tor_inet_aton(hostname, &in) == 0) {
    /* then we have to resolve it */
    log_debug(LD_CONFIG, "Local hostname '%s' is DNS address. "
              "Trying to resolve to IP address.", hostname);
    explicit_ip = 0;
    if (tor_lookup_hostname(hostname, &addr)) { /* failed to resolve */
      uint32_t interface_ip; /* host order */

      if (explicit_hostname) {
        log_fn(warn_severity, LD_CONFIG,
               "Could not resolve local Address '%s'. Failing.", hostname);
        return -1;
      }
      log_fn(notice_severity, LD_CONFIG,
             "Could not resolve guessed local hostname '%s'. "
             "Trying something else.", hostname);
      if (get_interface_address(warn_severity, &interface_ip)) {
        log_fn(warn_severity, LD_CONFIG,
               "Could not get local interface IP address. Failing.");
        return -1;
      }
      from_interface = 1;
      addr = interface_ip;
      log_fn(notice_severity, LD_CONFIG, "Learned IP address '%s' for "
             "local interface. Using that.", fmt_addr32(addr));
      strlcpy(hostname, "<guessed from interfaces>", sizeof(hostname));
    } else { /* resolved hostname into addr */
      tor_addr_from_ipv4h(&myaddr, addr);

      if (!explicit_hostname &&
          tor_addr_is_internal(&myaddr, 0)) {
        tor_addr_t interface_ip;

        log_fn(notice_severity, LD_CONFIG, "Guessed local hostname '%s' "
               "resolves to a private IP address (%s). Trying something "
               "else.", hostname, fmt_addr32(addr));

        if (get_interface_address6(warn_severity, AF_INET, &interface_ip)<0) {
          log_fn(warn_severity, LD_CONFIG,
                 "Could not get local interface IP address. Too bad.");
        } else if (tor_addr_is_internal(&interface_ip, 0)) {
          log_fn(notice_severity, LD_CONFIG,
                 "Interface IP address '%s' is a private address too. "
                 "Ignoring.", fmt_addr(&interface_ip));
        } else {
          from_interface = 1;
          addr = tor_addr_to_ipv4h(&interface_ip);
          log_fn(notice_severity, LD_CONFIG,
                 "Learned IP address '%s' for local interface."
                 " Using that.", fmt_addr32(addr));
          strlcpy(hostname, "<guessed from interfaces>", sizeof(hostname));
        }
      }
    }
  } else {
    log_debug(LD_CONFIG, "Local hostname '%s' is already IP address, "
              "skipping DNS resolution", hostname);
    addr = ntohl(in.s_addr); /* set addr so that addr_string is not
                              * illformed */
  }

  /*
   * Step three: Check whether 'addr' is an internal IP address, and error
   * out if it is and we don't want that.
   */

  tor_addr_from_ipv4h(&myaddr,addr);

  addr_string = tor_dup_ip(addr);
  if (addr_string && tor_addr_is_internal(&myaddr, 0)) {
    /* make sure we're ok with publishing an internal IP */
    if (using_default_dir_authorities(options)) {
      /* if they are using the default authorities, disallow internal IPs
       * always. For IPv6 ORPorts, this check is done in
       * router_get_advertised_ipv6_or_ap(). See #33681. */
      log_fn(warn_severity, LD_CONFIG,
             "Address '%s' resolves to private IP address '%s'. "
             "Tor servers that use the default DirAuthorities must have "
             "public IP addresses.", hostname, addr_string);
      tor_free(addr_string);
      return -1;
    }
    if (!explicit_ip) {
      /* even if they've set their own authorities, require an explicit IP if
       * they're using an internal address. */
      log_fn(warn_severity, LD_CONFIG, "Address '%s' resolves to private "
             "IP address '%s'. Please set the Address config option to be "
             "the IP address you want to use.", hostname, addr_string);
      tor_free(addr_string);
      return -1;
    }
  }

  /*
   * Step four: We have a winner! 'addr' is our answer for sure, and
   * 'addr_string' is its string form. Fill out the various fields to
   * say how we decided it.
   */

  log_debug(LD_CONFIG, "Resolved Address to '%s'.", addr_string);

  if (explicit_ip) {
    method_used = "CONFIGURED";
    hostname_used = NULL;
  } else if (explicit_hostname) {
    method_used = "RESOLVED";
    hostname_used = hostname;
  } else if (from_interface) {
    method_used = "INTERFACE";
    hostname_used = NULL;
  } else {
    method_used = "GETHOSTNAME";
    hostname_used = hostname;
  }

  *addr_out = addr;
  if (method_out)
    *method_out = method_used;
  if (hostname_out)
    *hostname_out = hostname_used ? tor_strdup(hostname_used) : NULL;

  /*
   * Step five: Check if the answer has changed since last time (or if
   * there was no last time), and if so call various functions to keep
   * us up-to-date.
   */

  if (last_resolved_addr && last_resolved_addr != *addr_out) {
    /* Leave this as a notice, regardless of the requested severity,
     * at least until dynamic IP address support becomes bulletproof. */
    log_notice(LD_NET,
               "Your IP address seems to have changed to %s "
               "(METHOD=%s%s%s). Updating.",
               addr_string, method_used,
               hostname_used ? " HOSTNAME=" : "",
               hostname_used ? hostname_used : "");
    ip_address_changed(0);
  }

  if (last_resolved_addr != *addr_out) {
    control_event_server_status(LOG_NOTICE,
                                "EXTERNAL_ADDRESS ADDRESS=%s METHOD=%s%s%s",
                                addr_string, method_used,
                                hostname_used ? " HOSTNAME=" : "",
                                hostname_used ? hostname_used : "");
  }
  last_resolved_addr = *addr_out;

  /*
   * And finally, clean up and return success.
   */

  tor_free(addr_string);
  return 0;
}

/** Return true iff <b>addr</b> is judged to be on the same network as us, or
 * on a private network.
 */
MOCK_IMPL(int,
is_local_addr, (const tor_addr_t *addr))
{
  if (tor_addr_is_internal(addr, 0))
    return 1;
  /* Check whether ip is on the same /24 as we are. */
  if (get_options()->EnforceDistinctSubnets == 0)
    return 0;
  if (tor_addr_family(addr) == AF_INET) {
    uint32_t ip = tor_addr_to_ipv4h(addr);

    /* It's possible that this next check will hit before the first time
     * resolve_my_address actually succeeds.  (For clients, it is likely that
     * resolve_my_address will never be called at all).  In those cases,
     * last_resolved_addr will be 0, and so checking to see whether ip is on
     * the same /24 as last_resolved_addr will be the same as checking whether
     * it was on net 0, which is already done by tor_addr_is_internal.
     */
    if ((last_resolved_addr & (uint32_t)0xffffff00ul)
        == (ip & (uint32_t)0xffffff00ul))
      return 1;
  }
  return 0;
}
