/* Copyright (c) 2001-2020, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file relay_find_addr.c
 * \brief Implement mechanism for a relay to find its address.
 **/

#include "core/or/or.h"

#include "app/config/config.h"
#include "app/config/resolve_addr.h"

#include "core/mainloop/mainloop.h"

#include "feature/control/control_events.h"
#include "feature/dircommon/dir_connection_st.h"
#include "feature/nodelist/dirlist.h"
#include "feature/relay/relay_find_addr.h"
#include "feature/relay/router.h"
#include "feature/relay/routermode.h"

/** Consider the address suggestion suggested_addr as a possible one to use as
 * our address.
 *
 * This is called when a valid NETINFO cell is received containing a candidate
 * for our address or when a directory sends us back the X-Your-Address-Is
 * header.
 *
 * The suggested address is ignored if it does NOT come from a trusted source.
 * At the moment, we only look a trusted directory authorities.
 *
 * The suggested address is ignored if it is internal or it is the same as the
 * given peer_addr which is the address from the endpoint that sent the
 * NETINFO cell.
 *
 * The identity_digest is NULL if this is an address suggested by a directory
 * since this is a plaintext connection.
 *
 * The suggested address is set in our suggested address cache if everything
 * passes. */
void
relay_address_new_suggestion(const tor_addr_t *suggested_addr,
                             const tor_addr_t *peer_addr,
                             const char *identity_digest)
{
  const or_options_t *options = get_options();

  tor_assert(suggested_addr);
  tor_assert(peer_addr);

  /* Non server should just ignore this suggestion. Clients don't need to
   * learn their address let alone cache it. */
  if (!server_mode(options)) {
    return;
  }

  /* Is the peer a trusted source? Ignore anything coming from non trusted
   * source. In this case, we only look at trusted directory authorities. */
  if (!router_addr_is_trusted_dir(peer_addr) ||
      (identity_digest && !router_digest_is_trusted_dir(identity_digest))) {
    return;
  }

  /* Ignore a suggestion that is an internal address or the same as the one
   * the peer address. */
  if (tor_addr_is_internal(suggested_addr, 0)) {
    /* Do not believe anyone who says our address is internal. */
    return;
  }
  if (tor_addr_eq(suggested_addr, peer_addr)) {
    /* Do not believe anyone who says our address is their address. */
    log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
           "A relay endpoint %s is telling us that their address is ours.",
           fmt_addr(peer_addr));
    return;
  }

  /* Save the suggestion in our cache. */
  resolved_addr_set_suggested(suggested_addr);
}

/** Find our address to be published in our descriptor. Three places are
 * looked at:
 *
 *    1. Resolved cache. Populated by find_my_address() during the relay
 *       periodic event that attempts to learn if our address has changed.
 *
 *    2. If flags is set with RELAY_FIND_ADDR_CACHE_ONLY, only the resolved
 *       and suggested cache are looked at. No address discovery will be done.
 *
 *    3. Finally, if all fails, use the suggested address cache which is
 *       populated by the NETINFO cell content or HTTP header from a
 *       directory.
 *
 * Return true on success and addr_out contains the address to use for the
 * given family. On failure to find the address, false is returned and
 * addr_out is set to an AF_UNSPEC address. */
MOCK_IMPL(bool,
relay_find_addr_to_publish, (const or_options_t *options, int family,
                             int flags, tor_addr_t *addr_out))
{
  tor_assert(options);
  tor_assert(addr_out);

  tor_addr_make_unspec(addr_out);

  /* If an IPv6 is requested, check if IPv6 address discovery is disabled on
   * this instance. If so, we return a failure. It is done here so we don't
   * query the suggested cache that might be populated with an IPv6. */
  if (family == AF_INET6 && options->AddressDisableIPv6) {
    return false;
  }

  /* First, check our resolved address cache. It should contain the address
   * we've discovered from the periodic relay event. */
  resolved_addr_get_last(family, addr_out);
  if (!tor_addr_is_null(addr_out)) {
    goto found;
  }

  /* Second, attempt to find our address. The following can do a DNS resolve
   * thus only do it when the no cache only flag is flipped. */
  if (!(flags & RELAY_FIND_ADDR_CACHE_ONLY)) {
    if (find_my_address(options, family, LOG_INFO, addr_out, NULL, NULL)) {
      goto found;
    }
  }

  /* Third, consider address from our suggestion cache. */
  resolved_addr_get_suggested(family, addr_out);
  if (!tor_addr_is_null(addr_out)) {
    goto found;
  }

  /* No publishable address was found. */
  return false;

 found:
  return true;
}

/** Return true iff this relay has an address set for the given family.
 *
 * This only checks the caches so it will not trigger a full discovery of the
 * address. */
bool
relay_has_address_set(int family)
{
  tor_addr_t addr;
  return relay_find_addr_to_publish(get_options(), family,
                                    RELAY_FIND_ADDR_CACHE_ONLY, &addr);
}
