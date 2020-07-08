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

/** We failed to resolve our address locally, but we'd like to build
 * a descriptor and publish / test reachability. If we have a guess
 * about our address based on directory headers, answer it and return
 * 0; else return -1. */
static int
router_guess_address_from_dir_headers(uint32_t *guess)
{
  if (!tor_addr_is_null(&last_guessed_ip)) {
    *guess = tor_addr_to_ipv4h(&last_guessed_ip);
    return 0;
  }
  return -1;
}

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

  /* This should never be called on a non Tor relay. */
  if (BUG(!server_mode(options))) {
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

/** Make a current best guess at our address, either because
 * it's configured in torrc, or because we've learned it from
 * dirserver headers. Place the answer in *<b>addr</b> and return
 * 0 on success, else return -1 if we have no guess.
 *
 * If <b>cache_only</b> is true, just return any cached answers, and
 * don't try to get any new answers.
 */
MOCK_IMPL(int,
router_pick_published_address, (const or_options_t *options, uint32_t *addr,
                                int cache_only))
{
  tor_addr_t last_resolved_addr;

  /* First, check the cached output from find_my_address(). */
  resolved_addr_get_last(AF_INET, &last_resolved_addr);
  if (!tor_addr_is_null(&last_resolved_addr)) {
    *addr = tor_addr_to_ipv4h(&last_resolved_addr);
    return 0;
  }

  /* Second, consider doing a resolve attempt right here. */
  if (!cache_only) {
    tor_addr_t my_addr;
    if (find_my_address(options, AF_INET, LOG_INFO, &my_addr, NULL, NULL)) {
      log_info(LD_CONFIG,"Success: chose address '%s'.", fmt_addr(&my_addr));
      *addr = tor_addr_to_ipv4h(&my_addr);
      return 0;
    }
  }

  /* Third, check the cached output from router_new_address_suggestion(). */
  if (router_guess_address_from_dir_headers(addr) >= 0)
    return 0;

  /* We have no useful cached answers. Return failure. */
  return -1;
}
