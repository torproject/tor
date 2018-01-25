/* Copyright (c) 2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/*
 * \file dos.c
 * \brief Implement Denial of Service mitigation subsystem.
 */

#define DOS_PRIVATE

#include "or.h"
#include "channel.h"
#include "config.h"
#include "geoip.h"
#include "main.h"
#include "networkstatus.h"

#include "dos.h"

/*
 * Circuit creation denial of service mitigation.
 *
 * Namespace used for this mitigation framework is "dos_cc_" where "cc" is for
 * Circuit Creation.
 */

/* Is the circuit creation DoS mitigation enabled? */
static unsigned int dos_cc_enabled = 0;

/* Consensus parameters. They can be changed when a new consensus arrives.
 * They are initialized with the hardcoded default values. */
static uint32_t dos_cc_min_concurrent_conn;
static uint32_t dos_cc_circuit_rate_tenths;
static uint32_t dos_cc_circuit_burst;
static dos_cc_defense_type_t dos_cc_defense_type;
static int32_t dos_cc_defense_time_period;

/*
 * Concurrent connection denial of service mitigation.
 *
 * Namespace used for this mitigation framework is "dos_conn_".
 */

/* Is the connection DoS mitigation enabled? */
static unsigned int dos_conn_enabled = 0;

/* Consensus parameters. They can be changed when a new consensus arrives.
 * They are initialized with the hardcoded default values. */
static uint32_t dos_conn_max_concurrent_count;
static dos_conn_defense_type_t dos_conn_defense_type;

/*
 * General interface of the denial of service mitigation subsystem.
 */

/* Return true iff the circuit creation mitigation is enabled. We look at the
 * consensus for this else a default value is returned. */
MOCK_IMPL(STATIC unsigned int,
get_param_cc_enabled, (const networkstatus_t *ns))
{
  if (get_options()->DoSCircuitCreationEnabled != -1) {
    return get_options()->DoSCircuitCreationEnabled;
  }

  return !!networkstatus_get_param(ns, "DoSCircuitCreationEnabled",
                                   DOS_CC_ENABLED_DEFAULT, 0, 1);
}

/* Return the parameter for the minimum concurrent connection at which we'll
 * start counting circuit for a specific client address. */
STATIC uint32_t
get_param_cc_min_concurrent_connection(const networkstatus_t *ns)
{
  if (get_options()->DoSCircuitCreationMinConnections) {
    return get_options()->DoSCircuitCreationMinConnections;
  }
  return networkstatus_get_param(ns, "DoSCircuitCreationMinConnections",
                                 DOS_CC_MIN_CONCURRENT_CONN_DEFAULT,
                                 1, INT32_MAX);
}

/* Return the parameter for the time rate that is how many circuits over this
 * time span. */
static uint32_t
get_param_cc_circuit_rate_tenths(const networkstatus_t *ns)
{
  /* This is in seconds. */
  if (get_options()->DoSCircuitCreationRateTenths) {
    return get_options()->DoSCircuitCreationRateTenths;
  }
  return networkstatus_get_param(ns, "DoSCircuitCreationRateTenths",
                                 DOS_CC_CIRCUIT_RATE_TENTHS_DEFAULT,
                                 1, INT32_MAX);
}

/* Return the parameter for the maximum circuit count for the circuit time
 * rate. */
STATIC uint32_t
get_param_cc_circuit_burst(const networkstatus_t *ns)
{
  if (get_options()->DoSCircuitCreationBurst) {
    return get_options()->DoSCircuitCreationBurst;
  }
  return networkstatus_get_param(ns, "DoSCircuitCreationBurst",
                                 DOS_CC_CIRCUIT_BURST_DEFAULT,
                                 1, INT32_MAX);
}

/* Return the consensus parameter of the circuit creation defense type. */
static uint32_t
get_param_cc_defense_type(const networkstatus_t *ns)
{
  if (get_options()->DoSCircuitCreationDefenseType) {
    return get_options()->DoSCircuitCreationDefenseType;
  }
  return networkstatus_get_param(ns, "DoSCircuitCreationDefenseType",
                                 DOS_CC_DEFENSE_TYPE_DEFAULT,
                                 DOS_CC_DEFENSE_NONE, DOS_CC_DEFENSE_MAX);
}

/* Return the consensus parameter of the defense time period which is how much
 * time should we defend against a malicious client address. */
static int32_t
get_param_cc_defense_time_period(const networkstatus_t *ns)
{
  /* Time in seconds. */
  if (get_options()->DoSCircuitCreationDefenseTimePeriod) {
    return get_options()->DoSCircuitCreationDefenseTimePeriod;
  }
  return networkstatus_get_param(ns, "DoSCircuitCreationDefenseTimePeriod",
                                 DOS_CC_DEFENSE_TIME_PERIOD_DEFAULT,
                                 0, INT32_MAX);
}

/* Return true iff connection mitigation is enabled. We look at the consensus
 * for this else a default value is returned. */
MOCK_IMPL(STATIC unsigned int,
get_param_conn_enabled, (const networkstatus_t *ns))
{
  if (get_options()->DoSConnectionEnabled != -1) {
    return get_options()->DoSConnectionEnabled;
  }
  return !!networkstatus_get_param(ns, "DoSConnectionEnabled",
                                   DOS_CONN_ENABLED_DEFAULT, 0, 1);
}

/* Return the consensus parameter for the maximum concurrent connection
 * allowed. */
STATIC uint32_t
get_param_conn_max_concurrent_count(const networkstatus_t *ns)
{
  if (get_options()->DoSConnectionMaxConcurrentCount) {
    return get_options()->DoSConnectionMaxConcurrentCount;
  }
  return networkstatus_get_param(ns, "DoSConnectionMaxConcurrentCount",
                                 DOS_CONN_MAX_CONCURRENT_COUNT_DEFAULT,
                                 1, INT32_MAX);
}

/* Return the consensus parameter of the connection defense type. */
static uint32_t
get_param_conn_defense_type(const networkstatus_t *ns)
{
  if (get_options()->DoSConnectionDefenseType) {
    return get_options()->DoSConnectionDefenseType;
  }
  return networkstatus_get_param(ns, "DoSConnectionDefenseType",
                                 DOS_CONN_DEFENSE_TYPE_DEFAULT,
                                 DOS_CONN_DEFENSE_NONE, DOS_CONN_DEFENSE_MAX);
}

/* Set circuit creation parameters located in the consensus or their default
 * if none are present. Called at initialization or when the consensus
 * changes. */
static void
set_dos_parameters(const networkstatus_t *ns)
{
  /* Get the default consensus param values. */
  dos_cc_enabled = get_param_cc_enabled(ns);
  dos_cc_min_concurrent_conn = get_param_cc_min_concurrent_connection(ns);
  dos_cc_circuit_rate_tenths = get_param_cc_circuit_rate_tenths(ns);
  dos_cc_circuit_burst = get_param_cc_circuit_burst(ns);
  dos_cc_defense_time_period = get_param_cc_defense_time_period(ns);
  dos_cc_defense_type = get_param_cc_defense_type(ns);

  /* Connection detection. */
  dos_conn_enabled = get_param_conn_enabled(ns);
  dos_conn_max_concurrent_count = get_param_conn_max_concurrent_count(ns);
  dos_conn_defense_type = get_param_conn_defense_type(ns);
}

/* Free everything for the circuit creation DoS mitigation subsystem. */
static void
cc_free_all(void)
{
  /* If everything is freed, the circuit creation subsystem is not enabled. */
  dos_cc_enabled = 0;
}

/* Called when the consensus has changed. Do appropriate actions for the
 * circuit creation subsystem. */
static void
cc_consensus_has_changed(const networkstatus_t *ns)
{
  /* Looking at the consensus, is the circuit creation subsystem enabled? If
   * not and it was enabled before, clean it up. */
  if (dos_cc_enabled && !get_param_cc_enabled(ns)) {
    cc_free_all();
  }
}

/* Concurrent connection private API. */

/* Free everything for the connection DoS mitigation subsystem. */
static void
conn_free_all(void)
{
  dos_conn_enabled = 0;
}

/* Called when the consensus has changed. Do appropriate actions for the
 * connection mitigation subsystem. */
static void
conn_consensus_has_changed(const networkstatus_t *ns)
{
  /* Looking at the consensus, is the connection mitigation subsystem enabled?
   * If not and it was enabled before, clean it up. */
  if (dos_conn_enabled && !get_param_conn_enabled(ns)) {
    conn_free_all();
  }
}

/* General private API */

/* Return true iff we have at least one DoS detection enabled. This is used to
 * decide if we need to allocate any kind of high level DoS object. */
static inline int
dos_is_enabled(void)
{
  return (dos_cc_enabled || dos_conn_enabled);
}

/* Circuit creation public API. */

/* Concurrent connection detection public API. */

/* General API */

/* Called when a new client connection has been established on the given
 * address. */
void
dos_new_client_conn(or_connection_t *or_conn)
{
  clientmap_entry_t *entry;

  tor_assert(or_conn);

  /* Past that point, we know we have at least one DoS detection subsystem
   * enabled so we'll start allocating stuff. */
  if (!dos_is_enabled()) {
    goto end;
  }

  /* We are only interested in client connection from the geoip cache. */
  entry = geoip_lookup_client(&or_conn->real_addr, NULL,
                              GEOIP_CLIENT_CONNECT);
  if (BUG(entry == NULL)) {
    /* Should never happen because we note down the address in the geoip
     * cache before this is called. */
    goto end;
  }

  entry->dos_stats.concurrent_count++;
  or_conn->tracked_for_dos_mitigation = 1;
  log_debug(LD_DOS, "Client address %s has now %u concurrent connections.",
            fmt_addr(&or_conn->real_addr),
            entry->dos_stats.concurrent_count);

 end:
  return;
}

/* Called when a client connection for the given IP address has been closed. */
void
dos_close_client_conn(const or_connection_t *or_conn)
{
  clientmap_entry_t *entry;

  tor_assert(or_conn);

  /* We have to decrement the count on tracked connection only even if the
   * subsystem has been disabled at runtime because it might be re-enabled
   * after and we need to keep a synchronized counter at all time. */
  if (!or_conn->tracked_for_dos_mitigation) {
    goto end;
  }

  /* We are only interested in client connection from the geoip cache. */
  entry = geoip_lookup_client(&or_conn->real_addr, NULL,
                              GEOIP_CLIENT_CONNECT);
  if (entry == NULL) {
    /* This can happen because we can close a connection before the channel
     * got to be noted down in the geoip cache. */
    goto end;
  }

  /* Extra super duper safety. Going below 0 means an underflow which could
   * lead to most likely a false positive. In theory, this should never happen
   * but lets be extra safe. */
  if (BUG(entry->dos_stats.concurrent_count == 0)) {
    goto end;
  }

  entry->dos_stats.concurrent_count--;
  log_debug(LD_DOS, "Client address %s has lost a connection. Concurrent "
                    "connections are now at %u",
            fmt_addr(&or_conn->real_addr),
            entry->dos_stats.concurrent_count);

 end:
  return;
}

/* Called when the consensus has changed. We might have new consensus
 * parameters to look at. */
void
dos_consensus_has_changed(const networkstatus_t *ns)
{
  cc_consensus_has_changed(ns);
  conn_consensus_has_changed(ns);

  /* We were already enabled or we just became enabled but either way, set the
   * consensus parameters for all subsystems. */
  set_dos_parameters(ns);
}

/* Return true iff the DoS mitigation subsystem is enabled. */
int
dos_enabled(void)
{
  return dos_is_enabled();
}

/* Free everything from the Denial of Service subsystem. */
void
dos_free_all(void)
{
  /* Free the circuit creation mitigation subsystem. It is safe to do this
   * even if it wasn't initialized. */
  cc_free_all();

  /* Free the connection mitigation subsystem. It is safe to do this even if
   * it wasn't initialized. */
  conn_free_all();
}

/* Initialize the Denial of Service subsystem. */
void
dos_init(void)
{
  /* To initialize, we only need to get the parameters. */
  set_dos_parameters(NULL);
}

