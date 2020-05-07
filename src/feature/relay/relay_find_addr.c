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

/** A directory server <b>d_conn</b> told us our IP address is
 * <b>suggestion</b>.
 * If this address is different from the one we think we are now, and
 * if our computer doesn't actually know its IP address, then switch. */
void
router_new_address_suggestion(const char *suggestion,
                              const dir_connection_t *d_conn)
{
  tor_addr_t addr;
  uint32_t cur = 0;             /* Current IPv4 address.  */
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
  cur = get_last_resolved_addr();
  if (cur ||
      resolve_my_address(LOG_INFO, options, &cur, NULL, NULL) >= 0) {
    /* We're all set -- we already know our address. Great. */
    tor_addr_from_ipv4h(&last_guessed_ip, cur); /* store it in case we
                                                   need it later */
    return;
  }
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
  /* First, check the cached output from resolve_my_address(). */
  *addr = get_last_resolved_addr();
  if (*addr)
    return 0;

  /* Second, consider doing a resolve attempt right here. */
  if (!cache_only) {
    if (resolve_my_address(LOG_INFO, options, addr, NULL, NULL) >= 0) {
      log_info(LD_CONFIG,"Success: chose address '%s'.", fmt_addr32(*addr));
      return 0;
    }
  }

  /* Third, check the cached output from router_new_address_suggestion(). */
  if (router_guess_address_from_dir_headers(addr) >= 0)
    return 0;

  /* We have no useful cached answers. Return failure. */
  return -1;
}
