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

/** The most recently guessed value of our IP address, based on directory
 * headers. */
static tor_addr_t last_guessed_ip = TOR_ADDR_NULL;

/** Consider the address suggestion suggested_addr as a possible one to use as
 * our address.
 *
 * This is called when a valid NETINFO cell is recevied containing a candidate
 * for our address.
 *
 * The suggested address is ignored if it does NOT come from a trusted source.
 * At the moment, we only look a trusted directory authorities.
 *
 * The suggested address is ignored if it is internal or it is the same as the
 * given peer_addr which is the address from the endpoint that sent the
 * NETINFO cell.
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
  tor_assert(identity_digest);

  /* Non server should just ignore this suggestion. Clients don't need to
   * learn their address let alone cache it. */
  if (!server_mode(options)) {
    return;
  }

  /* Is the peer a trusted source? Ignore anything coming from non trusted
   * source. In this case, we only look at trusted directory authorities. */
  if (!router_addr_is_trusted_dir(peer_addr) ||
      !router_digest_is_trusted_dir(identity_digest)) {
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

/** A directory server <b>d_conn</b> told us our IP address is
 * <b>suggestion</b>.
 * If this address is different from the one we think we are now, and
 * if our computer doesn't actually know its IP address, then switch. */
void
router_new_address_suggestion(const char *suggestion,
                              const dir_connection_t *d_conn)
{
  tor_addr_t addr, my_addr, last_resolved_addr;
  const or_options_t *options = get_options();

  /* first, learn what the IP address actually is */
  if (tor_addr_parse(&addr, suggestion) == -1) {
    log_debug(LD_DIR, "Malformed X-Your-Address-Is header %s. Ignoring.",
              escaped(suggestion));
    return;
  }

  log_debug(LD_DIR, "Got X-Your-Address-Is: %s.", suggestion);

  if (!server_mode(options)) {
    tor_addr_copy(&last_guessed_ip, &addr);
    return;
  }

  /* XXXX ipv6 */
  resolved_addr_get_last(AF_INET, &last_resolved_addr);
  if (!tor_addr_is_null(&last_resolved_addr)) {
    /* Lets use this one. */
    tor_addr_copy(&last_guessed_ip, &last_resolved_addr);
    return;
  }

  /* Attempt to find our address. */
  if (find_my_address(options, AF_INET, LOG_INFO, &my_addr, NULL, NULL)) {
    /* We're all set -- we already know our address. Great. */
    tor_addr_copy(&last_guessed_ip, &my_addr); /* store it in case we
                                                  need it later */
    return;
  }

  /* Consider the suggestion from the directory. */
  if (tor_addr_is_internal(&addr, 0)) {
    /* Don't believe anybody who says our IP is, say, 127.0.0.1. */
    return;
  }
  if (tor_addr_eq(&d_conn->base_.addr, &addr)) {
    /* Don't believe anybody who says our IP is their IP. */
    log_debug(LD_DIR, "A directory server told us our IP address is %s, "
              "but they are just reporting their own IP address. Ignoring.",
              suggestion);
    return;
  }

  /* Okay.  We can't resolve our own address, and X-Your-Address-Is is giving
   * us an answer different from what we had the last time we managed to
   * resolve it. */
  if (!tor_addr_eq(&last_guessed_ip, &addr)) {
    control_event_server_status(LOG_NOTICE,
                                "EXTERNAL_ADDRESS ADDRESS=%s METHOD=DIRSERV",
                                suggestion);
    log_addr_has_changed(LOG_NOTICE, &last_guessed_ip, &addr,
                         d_conn->base_.address);
    ip_address_changed(0);
    tor_addr_copy(&last_guessed_ip, &addr); /* router_rebuild_descriptor()
                                               will fetch it */
  }
}

/** Find our address to be published in our descriptor. Three places are
 * looked at:
 *
 *    1. Resolved cache. Populated by find_my_address() during the relay
 *       periodic event that attempts to learn if our address has changed.
 *
 *    2. If cache_only is false, attempt to find the address using the
 *       relay_find_addr.h interface.
 *
 *    3. Finally, if all fails, use the suggested address cache which is
 *       populated by the NETINFO cell values.
 *
 * Return true on success and addr_out contains the address to use for the
 * given family. On failure to find the address, false is returned and
 * addr_out is set to an AF_UNSPEC address. */
MOCK_IMPL(bool,
relay_find_addr_to_publish, (const or_options_t *options, int family,
                             bool cache_only, tor_addr_t *addr_out))
{
  tor_assert(options);
  tor_assert(addr_out);

  tor_addr_make_unspec(addr_out);

  /* First, check our resolved address cache. It should contain the address
   * we've discovered from the periodic relay event. */
  resolved_addr_get_last(family, addr_out);
  if (!tor_addr_is_null(addr_out)) {
    goto found;
  }

  /* Second, attempt to find our address. The following can do a DNS resolve
   * thus only do it when the no cache only flag is flipped. */
  if (!cache_only) {
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
  return relay_find_addr_to_publish(get_options(), family, 1, &addr);
}
