/* Copyright (c) 2014-2020, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#define STATUS_PRIVATE
#define HIBERNATE_PRIVATE
#define LOG_PRIVATE
#define REPHIST_PRIVATE

#include "orconfig.h"

#include <float.h>
#include <math.h>

#include "core/or/or.h"
#include "lib/log/log.h"
#include "tor_queue.h"
#include "core/or/status.h"
#include "core/or/circuitlist.h"
#include "app/config/config.h"
#include "feature/hibernate/hibernate.h"
#include "feature/stats/rephist.h"
#include "core/or/relay.h"
#include "feature/relay/router.h"
#include "feature/relay/routermode.h"
#include "core/mainloop/mainloop.h"
#include "feature/nodelist/nodelist.h"
#include "app/config/statefile.h"
#include "lib/tls/tortls.h"

#include "core/or/origin_circuit_st.h"
#include "app/config/or_state_st.h"
#include "feature/nodelist/routerinfo_st.h"

#include "test/test.h"

/*
 * Test that count_circuits() is correctly counting the number of
 * global circuits.
 */

static smartlist_t * mock_global_circuitlist = NULL;

static smartlist_t * status_count_circuits_circuit_get_global_list(void);

static void
test_status_count_circuits(void *arg)
{
  /* Choose origin_circuit_t wlog. */
  origin_circuit_t *mock_circuit1, *mock_circuit2;
  int expected_circuits = 2, actual_circuits;

  (void)arg;

  mock_circuit1 = tor_malloc_zero(sizeof(origin_circuit_t));
  mock_circuit2 = tor_malloc_zero(sizeof(origin_circuit_t));
  mock_global_circuitlist = smartlist_new();
  smartlist_add(mock_global_circuitlist, TO_CIRCUIT(mock_circuit1));
  smartlist_add(mock_global_circuitlist, TO_CIRCUIT(mock_circuit2));

  MOCK(circuit_get_global_list,
       status_count_circuits_circuit_get_global_list);

  actual_circuits = count_circuits();

  tt_assert(expected_circuits == actual_circuits);

 done:
  tor_free(mock_circuit1);
  tor_free(mock_circuit2);
  smartlist_free(mock_global_circuitlist);
  mock_global_circuitlist = NULL;
  UNMOCK(circuit_get_global_list);
}

static smartlist_t *
status_count_circuits_circuit_get_global_list(void)
{
  return mock_global_circuitlist;
}

/*
 * Test that secs_to_uptime() is converting the number of seconds that
 * Tor is up for into the appropriate string form containing hours and minutes.
 */

static void
test_status_secs_to_uptime(void *arg)
{
  const char *expected;
  char *actual;
  (void)arg;

  expected = "0:00 hours";
  actual = secs_to_uptime(0);
  tt_str_op(actual, OP_EQ, expected);
  tor_free(actual);

  expected = "0:00 hours";
  actual = secs_to_uptime(1);
  tt_str_op(actual, OP_EQ, expected);
  tor_free(actual);

  expected = "0:01 hours";
  actual = secs_to_uptime(60);
  tt_str_op(actual, OP_EQ, expected);
  tor_free(actual);

  expected = "0:59 hours";
  actual = secs_to_uptime(60 * 59);
  tt_str_op(actual, OP_EQ, expected);
  tor_free(actual);

  expected = "1:00 hours";
  actual = secs_to_uptime(60 * 60);
  tt_str_op(actual, OP_EQ, expected);
  tor_free(actual);

  expected = "23:59 hours";
  actual = secs_to_uptime(60 * 60 * 23 + 60 * 59);
  tt_str_op(actual, OP_EQ, expected);
  tor_free(actual);

  expected = "1 day 0:00 hours";
  actual = secs_to_uptime(60 * 60 * 23 + 60 * 60);
  tt_str_op(actual, OP_EQ, expected);
  tor_free(actual);

  expected = "1 day 0:00 hours";
  actual = secs_to_uptime(86400 + 1);
  tt_str_op(actual, OP_EQ, expected);
  tor_free(actual);

  expected = "1 day 0:01 hours";
  actual = secs_to_uptime(86400 + 60);
  tt_str_op(actual, OP_EQ, expected);
  tor_free(actual);

  expected = "10 days 0:00 hours";
  actual = secs_to_uptime(86400 * 10);
  tt_str_op(actual, OP_EQ, expected);
  tor_free(actual);

  expected = "10 days 0:00 hours";
  actual = secs_to_uptime(864000 + 1);
  tt_str_op(actual, OP_EQ, expected);
  tor_free(actual);

  expected = "10 days 0:01 hours";
  actual = secs_to_uptime(864000 + 60);
  tt_str_op(actual, OP_EQ, expected);
  tor_free(actual);

  done:
    if (actual != NULL)
      tor_free(actual);
}

/*
 * Test that bytes_to_usage() is correctly converting the number of bytes that
 * Tor has read/written into the appropriate string form containing kilobytes,
 * megabytes, or gigabytes.
 */

static void
test_status_bytes_to_usage(void *arg)
{
  const char *expected;
  char *actual;
  (void)arg;

  expected = "0 kB";
  actual = bytes_to_usage(0);
  tt_str_op(actual, OP_EQ, expected);
  tor_free(actual);

  expected = "0 kB";
  actual = bytes_to_usage(1);
  tt_str_op(actual, OP_EQ, expected);
  tor_free(actual);

  expected = "1 kB";
  actual = bytes_to_usage(1024);
  tt_str_op(actual, OP_EQ, expected);
  tor_free(actual);

  expected = "1023 kB";
  actual = bytes_to_usage((1 << 20) - 1);
  tt_str_op(actual, OP_EQ, expected);
  tor_free(actual);

  expected = "1.00 MB";
  actual = bytes_to_usage((1 << 20));
  tt_str_op(actual, OP_EQ, expected);
  tor_free(actual);

  expected = "1.00 MB";
  actual = bytes_to_usage((1 << 20) + 5242);
  tt_str_op(actual, OP_EQ, expected);
  tor_free(actual);

  expected = "1.01 MB";
  actual = bytes_to_usage((1 << 20) + 5243);
  tt_str_op(actual, OP_EQ, expected);
  tor_free(actual);

  expected = "1024.00 MB";
  actual = bytes_to_usage((1 << 30) - 1);
  tt_str_op(actual, OP_EQ, expected);
  tor_free(actual);

  expected = "1.00 GB";
  actual = bytes_to_usage((1 << 30));
  tt_str_op(actual, OP_EQ, expected);
  tor_free(actual);

  expected = "1.00 GB";
  actual = bytes_to_usage((1 << 30) + 5368709);
  tt_str_op(actual, OP_EQ, expected);
  tor_free(actual);

  expected = "1.01 GB";
  actual = bytes_to_usage((1 << 30) + 5368710);
  tt_str_op(actual, OP_EQ, expected);
  tor_free(actual);

  expected = "10.00 GB";
  actual = bytes_to_usage((UINT64_C(1) << 30) * 10L);
  tt_str_op(actual, OP_EQ, expected);
  tor_free(actual);

  done:
    if (actual != NULL)
      tor_free(actual);
}

/*
 * Tests that log_heartbeat() fails when in the public server mode,
 * not hibernating, and we couldn't get the current routerinfo.
 */

static double status_hb_fails_tls_get_write_overhead_ratio(void);
static int status_hb_fails_we_are_hibernating(void);
static int status_hb_fails_public_server_mode(const or_options_t *options);
static const routerinfo_t * status_hb_fails_router_get_my_routerinfo(void);

static void
test_status_hb_fails(void *arg)
{
  int expected, actual;
  (void)arg;

  MOCK(tls_get_write_overhead_ratio,
       status_hb_fails_tls_get_write_overhead_ratio);
  MOCK(we_are_hibernating,
       status_hb_fails_we_are_hibernating);
  MOCK(public_server_mode,
       status_hb_fails_public_server_mode);
  MOCK(router_get_my_routerinfo,
       status_hb_fails_router_get_my_routerinfo);

  expected = -1;
  actual = log_heartbeat(0);

  tt_int_op(actual, OP_EQ, expected);

  done:
    UNMOCK(tls_get_write_overhead_ratio);
    UNMOCK(we_are_hibernating);
    UNMOCK(public_server_mode);
    UNMOCK(router_get_my_routerinfo);
}

static double
status_hb_fails_tls_get_write_overhead_ratio(void)
{
  return 2.0;
}

static int
status_hb_fails_we_are_hibernating(void)
{
  return 0;
}

static int
status_hb_fails_public_server_mode(const or_options_t *options)
{
  (void)options;

  return 1;
}

static const routerinfo_t *
status_hb_fails_router_get_my_routerinfo(void)
{
  return NULL;
}

/*
 * Tests that log_heartbeat() logs appropriately if we are not in the cached
 * consensus.
 */

static double status_hb_not_in_consensus_tls_get_write_overhead_ratio(void);
static int status_hb_not_in_consensus_we_are_hibernating(void);
static int status_hb_not_in_consensus_public_server_mode(
             const or_options_t *options);
static const routerinfo_t *status_hb_not_in_consensus_get_my_routerinfo(void);
static const node_t * status_hb_not_in_consensus_node_get_by_id(
             const char *identity_digest);
static void status_hb_not_in_consensus_logv(
             int severity, log_domain_mask_t domain, const char *funcname,
             const char *suffix, const char *format, va_list ap);
static int status_hb_not_in_consensus_logv_called = 0;
static int status_hb_not_in_consensus_server_mode(const or_options_t *options);

static routerinfo_t *mock_routerinfo;

static void
test_status_hb_not_in_consensus(void *arg)
{
  int expected, actual;
  (void)arg;

  MOCK(tls_get_write_overhead_ratio,
       status_hb_not_in_consensus_tls_get_write_overhead_ratio);
  MOCK(we_are_hibernating,
       status_hb_not_in_consensus_we_are_hibernating);
  MOCK(public_server_mode,
       status_hb_not_in_consensus_public_server_mode);
  MOCK(router_get_my_routerinfo,
       status_hb_not_in_consensus_get_my_routerinfo);
  MOCK(node_get_by_id,
       status_hb_not_in_consensus_node_get_by_id);
  MOCK(logv,
       status_hb_not_in_consensus_logv);
  MOCK(server_mode,
       status_hb_not_in_consensus_server_mode);

  log_global_min_severity_ = LOG_DEBUG;
  onion_handshakes_requested[ONION_HANDSHAKE_TYPE_TAP] = 1;
  onion_handshakes_assigned[ONION_HANDSHAKE_TYPE_TAP] = 1;
  onion_handshakes_requested[ONION_HANDSHAKE_TYPE_NTOR] = 1;
  onion_handshakes_assigned[ONION_HANDSHAKE_TYPE_NTOR] = 1;

  expected = 0;
  actual = log_heartbeat(0);

  tt_int_op(actual, OP_EQ, expected);
  tt_int_op(status_hb_not_in_consensus_logv_called, OP_EQ, 6);

  done:
    UNMOCK(tls_get_write_overhead_ratio);
    UNMOCK(we_are_hibernating);
    UNMOCK(public_server_mode);
    UNMOCK(router_get_my_routerinfo);
    UNMOCK(node_get_by_id);
    UNMOCK(logv);
    UNMOCK(server_mode);
    tor_free(mock_routerinfo);
}

static double
status_hb_not_in_consensus_tls_get_write_overhead_ratio(void)
{
  return 1.0;
}

static int
status_hb_not_in_consensus_we_are_hibernating(void)
{
  return 0;
}

static int
status_hb_not_in_consensus_public_server_mode(const or_options_t *options)
{
  (void)options;

  return 1;
}

static const routerinfo_t *
status_hb_not_in_consensus_get_my_routerinfo(void)
{
  mock_routerinfo = tor_malloc(sizeof(routerinfo_t));

  return mock_routerinfo;
}

static const node_t *
status_hb_not_in_consensus_node_get_by_id(const char *identity_digest)
{
  (void)identity_digest;

  return NULL;
}

static void
status_hb_not_in_consensus_logv(int severity, log_domain_mask_t domain,
  const char *funcname, const char *suffix, const char *format, va_list ap)
{
  switch (status_hb_not_in_consensus_logv_called)
  {
    case 0:
      tt_int_op(severity, OP_EQ, LOG_NOTICE);
      tt_u64_op(domain, OP_EQ, LD_HEARTBEAT);
      tt_ptr_op(strstr(funcname, "log_heartbeat"), OP_NE, NULL);
      tt_ptr_op(suffix, OP_EQ, NULL);
      tt_str_op(format, OP_EQ,
          "Heartbeat: It seems like we are not in the cached consensus.");
      break;
    case 1:
      tt_int_op(severity, OP_EQ, LOG_NOTICE);
      tt_u64_op(domain, OP_EQ, LD_HEARTBEAT);
      tt_ptr_op(strstr(funcname, "log_heartbeat"), OP_NE, NULL);
      tt_ptr_op(suffix, OP_EQ, NULL);
      tt_str_op(format, OP_EQ,
          "Heartbeat: Tor's uptime is %s, with %d circuits open. "
          "I've sent %s and received %s.%s");
      tt_str_op(va_arg(ap, char *), OP_EQ, "0:00 hours");  /* uptime */
      tt_int_op(va_arg(ap, int), OP_EQ, 0);  /* count_circuits() */
      tt_str_op(va_arg(ap, char *), OP_EQ, "0 kB");  /* bw_sent */
      tt_str_op(va_arg(ap, char *), OP_EQ, "0 kB");  /* bw_rcvd */
      tt_str_op(va_arg(ap, char *), OP_EQ, "");  /* hibernating */
      break;
    case 2:
      tt_int_op(severity, OP_EQ, LOG_INFO);
      break;
    case 3:
      tt_int_op(severity, OP_EQ, LOG_NOTICE);
      tt_u64_op(domain, OP_EQ, LD_HEARTBEAT);
      tt_ptr_op(strstr(funcname, "rep_hist_log_circuit_handshake_stats"),
                OP_NE, NULL);
      tt_ptr_op(suffix, OP_EQ, NULL);
      tt_str_op(format, OP_EQ,
        "Circuit handshake stats since last time: %d/%d TAP, %d/%d NTor.");
      tt_int_op(va_arg(ap, int), OP_EQ, 1);  /* handshakes assigned (TAP) */
      tt_int_op(va_arg(ap, int), OP_EQ, 1);  /* handshakes requested (TAP) */
      tt_int_op(va_arg(ap, int), OP_EQ, 1);  /* handshakes assigned (NTOR) */
      tt_int_op(va_arg(ap, int), OP_EQ, 1);  /* handshakes requested (NTOR) */
      break;
    case 4:
      tt_int_op(severity, OP_EQ, LOG_NOTICE);
      tt_u64_op(domain, OP_EQ, LD_HEARTBEAT);
      tt_ptr_op(strstr(funcname, "rep_hist_log_link_protocol_counts"),
                OP_NE, NULL);
      break;
    case 5:
      tt_int_op(severity, OP_EQ, LOG_NOTICE);
      tt_u64_op(domain, OP_EQ, LD_HEARTBEAT);
      tt_str_op(format, OP_EQ, "DoS mitigation since startup:%s%s%s%s%s");
      tt_str_op(va_arg(ap, char *), OP_EQ,
                " 0 circuits killed with too many cells.");
      tt_str_op(va_arg(ap, char *), OP_EQ, " [cc not enabled]");
      tt_str_op(va_arg(ap, char *), OP_EQ, " [conn not enabled]");
      tt_str_op(va_arg(ap, char *), OP_EQ, "");
      tt_str_op(va_arg(ap, char *), OP_EQ, " 0 INTRODUCE2 rejected.");
      break;
    default:
      tt_abort_msg("unexpected call to logv()");  // TODO: prettyprint args
      break;
  }

  done:
    status_hb_not_in_consensus_logv_called++;
}

static int
status_hb_not_in_consensus_server_mode(const or_options_t *options)
{
  (void)options;

  return 0;
}

/*
 * Tests that log_heartbeat() correctly logs heartbeat information
 * normally.
 */

static double status_hb_simple_tls_get_write_overhead_ratio(void);
static int status_hb_simple_we_are_hibernating(void);
static int status_hb_simple_public_server_mode(const or_options_t *options);
static long status_hb_simple_get_uptime(void);
static uint64_t status_hb_simple_get_bytes_read(void);
static uint64_t status_hb_simple_get_bytes_written(void);
static void status_hb_simple_logv(int severity, log_domain_mask_t domain,
                                  const char *funcname, const char *suffix,
                                  const char *format, va_list ap);
ATTR_UNUSED static int status_hb_simple_logv_called = 0;
static int status_hb_simple_server_mode(const or_options_t *options);

static int status_hb_simple_n_msgs = 0;

static void
test_status_hb_simple(void *arg)
{
  int expected, actual;
  (void)arg;

  MOCK(tls_get_write_overhead_ratio,
       status_hb_simple_tls_get_write_overhead_ratio);
  MOCK(we_are_hibernating,
       status_hb_simple_we_are_hibernating);
  MOCK(public_server_mode,
       status_hb_simple_public_server_mode);
  MOCK(get_uptime,
       status_hb_simple_get_uptime);
  MOCK(get_bytes_read,
       status_hb_simple_get_bytes_read);
  MOCK(get_bytes_written,
       status_hb_simple_get_bytes_written);
  MOCK(logv,
       status_hb_simple_logv);
  MOCK(server_mode,
       status_hb_simple_server_mode);

  log_global_min_severity_ = LOG_DEBUG;

  expected = 0;
  actual = log_heartbeat(0);

  tt_int_op(actual, OP_EQ, expected);
  tt_int_op(status_hb_simple_n_msgs, OP_EQ, 1);

  done:
    UNMOCK(tls_get_write_overhead_ratio);
    UNMOCK(we_are_hibernating);
    UNMOCK(public_server_mode);
    UNMOCK(get_uptime);
    UNMOCK(get_bytes_read);
    UNMOCK(get_bytes_written);
    UNMOCK(logv);
    UNMOCK(server_mode);
}

static double
status_hb_simple_tls_get_write_overhead_ratio(void)
{
  return 1.0;
}

static int
status_hb_simple_we_are_hibernating(void)
{
  return 1;
}

static int
status_hb_simple_public_server_mode(const or_options_t *options)
{
  (void)options;

  return 0;
}

static long
status_hb_simple_get_uptime(void)
{
  return 0;
}

static uint64_t
status_hb_simple_get_bytes_read(void)
{
  return 0;
}

static uint64_t
status_hb_simple_get_bytes_written(void)
{
  return 0;
}

static void
status_hb_simple_logv(int severity, log_domain_mask_t domain,
  const char *funcname,
  const char *suffix, const char *format, va_list ap)
{
  if (severity == LOG_INFO)
    return;
  ++status_hb_simple_n_msgs;

  tt_int_op(severity, OP_EQ, LOG_NOTICE);
  tt_u64_op(domain, OP_EQ, LD_HEARTBEAT);
  tt_ptr_op(strstr(funcname, "log_heartbeat"), OP_NE, NULL);
  tt_ptr_op(suffix, OP_EQ, NULL);
  tt_str_op(format, OP_EQ,
      "Heartbeat: Tor's uptime is %s, with %d circuits open. "
      "I've sent %s and received %s.%s");
  tt_str_op(va_arg(ap, char *), OP_EQ, "0:00 hours");  /* uptime */
  tt_int_op(va_arg(ap, int), OP_EQ, 0);  /* count_circuits() */
  tt_str_op(va_arg(ap, char *), OP_EQ, "0 kB");  /* bw_sent */
  tt_str_op(va_arg(ap, char *), OP_EQ, "0 kB");  /* bw_rcvd */
  tt_str_op(va_arg(ap, char *), OP_EQ, " We are currently hibernating.");

  done:
    ;
}

static int
status_hb_simple_server_mode(const or_options_t *options)
{
  (void)options;

  return 0;
}

/*
 * Tests that log_heartbeat() correctly logs heartbeat information
 * and accounting information when configured.
 */

static double status_hb_calls_log_accounting_tls_get_write_overhead_ratio(
                       void);
static int status_hb_calls_log_accounting_we_are_hibernating(void);
static int status_hb_calls_log_accounting_public_server_mode(
                      const or_options_t *options);
static long status_hb_calls_log_accounting_get_uptime(void);
static uint64_t status_hb_calls_log_accounting_get_bytes_read(void);
static uint64_t status_hb_calls_log_accounting_get_bytes_written(void);
static void status_hb_calls_log_accounting_logv(
                      int severity, log_domain_mask_t domain,
                      const char *funcname, const char *suffix,
                      const char *format, va_list ap);
static int status_hb_calls_log_accounting_logv_called = 0;
static int status_hb_calls_log_accounting_server_mode(
                      const or_options_t *options);
static or_state_t * status_hb_calls_log_accounting_get_or_state(void);
static int status_hb_calls_log_accounting_accounting_is_enabled(
                      const or_options_t *options);
static time_t status_hb_calls_log_accounting_accounting_get_end_time(void);

static or_state_t * status_hb_calls_log_accounting_mock_state = NULL;
static or_options_t * status_hb_calls_log_accounting_mock_options = NULL;

static void
test_status_hb_calls_log_accounting(void *arg)
{
  int expected, actual;
  (void)arg;

  MOCK(tls_get_write_overhead_ratio,
       status_hb_calls_log_accounting_tls_get_write_overhead_ratio);
  MOCK(we_are_hibernating,
       status_hb_calls_log_accounting_we_are_hibernating);
  MOCK(public_server_mode,
       status_hb_calls_log_accounting_public_server_mode);
  MOCK(get_uptime,
       status_hb_calls_log_accounting_get_uptime);
  MOCK(get_bytes_read,
       status_hb_calls_log_accounting_get_bytes_read);
  MOCK(get_bytes_written,
       status_hb_calls_log_accounting_get_bytes_written);
  MOCK(logv,
       status_hb_calls_log_accounting_logv);
  MOCK(server_mode,
       status_hb_calls_log_accounting_server_mode);
  MOCK(get_or_state,
       status_hb_calls_log_accounting_get_or_state);
  MOCK(accounting_is_enabled,
       status_hb_calls_log_accounting_accounting_is_enabled);
  MOCK(accounting_get_end_time,
       status_hb_calls_log_accounting_accounting_get_end_time);

  log_global_min_severity_ = LOG_DEBUG;

  expected = 0;
  actual = log_heartbeat(0);

  tt_int_op(actual, OP_EQ, expected);
  tt_int_op(status_hb_calls_log_accounting_logv_called, OP_EQ, 3);

  done:
    UNMOCK(tls_get_write_overhead_ratio);
    UNMOCK(we_are_hibernating);
    UNMOCK(public_server_mode);
    UNMOCK(get_uptime);
    UNMOCK(get_bytes_read);
    UNMOCK(get_bytes_written);
    UNMOCK(logv);
    UNMOCK(server_mode);
    UNMOCK(accounting_is_enabled);
    UNMOCK(accounting_get_end_time);
    tor_free_(status_hb_calls_log_accounting_mock_state);
    tor_free_(status_hb_calls_log_accounting_mock_options);
}

static double
status_hb_calls_log_accounting_tls_get_write_overhead_ratio(void)
{
  return 1.0;
}

static int
status_hb_calls_log_accounting_we_are_hibernating(void)
{
  return 0;
}

static int
status_hb_calls_log_accounting_public_server_mode(const or_options_t *options)
{
  (void)options;

  return 0;
}

static long
status_hb_calls_log_accounting_get_uptime(void)
{
  return 0;
}

static uint64_t
status_hb_calls_log_accounting_get_bytes_read(void)
{
  return 0;
}

static uint64_t
status_hb_calls_log_accounting_get_bytes_written(void)
{
  return 0;
}

static void
status_hb_calls_log_accounting_logv(int severity, log_domain_mask_t domain,
  const char *funcname, const char *suffix, const char *format, va_list ap)
{
  switch (status_hb_calls_log_accounting_logv_called)
  {
    case 0:
      tt_int_op(severity, OP_EQ, LOG_NOTICE);
      tt_u64_op(domain, OP_EQ, LD_HEARTBEAT);
      tt_ptr_op(strstr(funcname, "log_heartbeat"), OP_NE, NULL);
      tt_ptr_op(suffix, OP_EQ, NULL);
      tt_str_op(format, OP_EQ,
          "Heartbeat: Tor's uptime is %s, with %d circuits open. "
          "I've sent %s and received %s.%s");
      tt_str_op(va_arg(ap, char *), OP_EQ, "0:00 hours");  /* uptime */
      tt_int_op(va_arg(ap, int), OP_EQ, 0);  /* count_circuits() */
      tt_str_op(va_arg(ap, char *), OP_EQ, "0 kB");  /* bw_sent */
      tt_str_op(va_arg(ap, char *), OP_EQ, "0 kB");  /* bw_rcvd */
      tt_str_op(va_arg(ap, char *), OP_EQ, "");  /* hibernating */
      break;
    case 1:
      tt_int_op(severity, OP_EQ, LOG_NOTICE);
      tt_u64_op(domain, OP_EQ, LD_HEARTBEAT);
      tt_ptr_op(strstr(funcname, "log_accounting"), OP_NE, NULL);
      tt_ptr_op(suffix, OP_EQ, NULL);
      tt_str_op(format, OP_EQ,
          "Heartbeat: Accounting enabled. Sent: %s, Received: %s, Used: %s / "
          "%s, Rule: %s. The current accounting interval ends on %s, in %s.");
      tt_str_op(va_arg(ap, char *), OP_EQ, "0 kB");  /* acc_sent */
      tt_str_op(va_arg(ap, char *), OP_EQ, "0 kB");  /* acc_rcvd */
      tt_str_op(va_arg(ap, char *), OP_EQ, "0 kB");  /* acc_used */
      tt_str_op(va_arg(ap, char *), OP_EQ, "0 kB");  /* acc_max */
      tt_str_op(va_arg(ap, char *), OP_EQ, "max");  /* acc_rule */
      /* format_local_iso_time uses local tz, so we can't just compare
       * the string against a constant */
      char datetime[ISO_TIME_LEN+1];
      format_local_iso_time(datetime, 60);
      tt_str_op(va_arg(ap, char *), OP_EQ, datetime); /* end_buf */
      tt_str_op(va_arg(ap, char *), OP_EQ, "0:01 hours");   /* remaining */
      break;
    case 2:
      tt_int_op(severity, OP_EQ, LOG_INFO);
      break;
    default:
      tt_abort_msg("unexpected call to logv()");  // TODO: prettyprint args
      break;
  }

  done:
    status_hb_calls_log_accounting_logv_called++;
}

static int
status_hb_calls_log_accounting_server_mode(const or_options_t *options)
{
  (void)options;

  return 1;
}

static int
status_hb_calls_log_accounting_accounting_is_enabled(
                                        const or_options_t *options)
{
  (void)options;

  return 1;
}

static time_t
status_hb_calls_log_accounting_accounting_get_end_time(void)
{
  return 60;
}

static or_state_t *
status_hb_calls_log_accounting_get_or_state(void)
{
  status_hb_calls_log_accounting_mock_state =
    tor_malloc_zero(sizeof(or_state_t));
  status_hb_calls_log_accounting_mock_state
    ->AccountingBytesReadInInterval = 0;
  status_hb_calls_log_accounting_mock_state
    ->AccountingBytesWrittenInInterval = 0;

  return status_hb_calls_log_accounting_mock_state;
}

/*
 * Tests that log_heartbeat() correctly logs packaged cell
 * fullness information.
 */

static double status_hb_packaged_cell_fullness_tls_get_write_overhead_ratio(
                          void);
static int status_hb_packaged_cell_fullness_we_are_hibernating(void);
static int status_hb_packaged_cell_fullness_public_server_mode(
                          const or_options_t *options);
static long status_hb_packaged_cell_fullness_get_uptime(void);
static uint64_t status_hb_packaged_cell_fullness_get_bytes_read(void);
static uint64_t status_hb_packaged_cell_fullness_get_bytes_written(void);
static void status_hb_packaged_cell_fullness_logv(
                          int severity, log_domain_mask_t domain,
                          const char *funcname, const char *suffix,
                          const char *format, va_list ap);
static int status_hb_packaged_cell_fullness_logv_called = 0;
static int status_hb_packaged_cell_fullness_server_mode(
                          const or_options_t *options);
static int status_hb_packaged_cell_fullness_accounting_is_enabled(
                          const or_options_t *options);

static void
test_status_hb_packaged_cell_fullness(void *arg)
{
  int expected, actual;
  (void)arg;

  MOCK(tls_get_write_overhead_ratio,
       status_hb_packaged_cell_fullness_tls_get_write_overhead_ratio);
  MOCK(we_are_hibernating,
       status_hb_packaged_cell_fullness_we_are_hibernating);
  MOCK(public_server_mode,
       status_hb_packaged_cell_fullness_public_server_mode);
  MOCK(get_uptime,
       status_hb_packaged_cell_fullness_get_uptime);
  MOCK(get_bytes_read,
       status_hb_packaged_cell_fullness_get_bytes_read);
  MOCK(get_bytes_written,
       status_hb_packaged_cell_fullness_get_bytes_written);
  MOCK(logv,
       status_hb_packaged_cell_fullness_logv);
  MOCK(server_mode,
       status_hb_packaged_cell_fullness_server_mode);
  MOCK(accounting_is_enabled,
       status_hb_packaged_cell_fullness_accounting_is_enabled);
  log_global_min_severity_ = LOG_DEBUG;

  stats_n_data_bytes_packaged = RELAY_PAYLOAD_SIZE;
  stats_n_data_cells_packaged = 2;
  expected = 0;
  actual = log_heartbeat(0);

  tt_int_op(actual, OP_EQ, expected);
  tt_int_op(status_hb_packaged_cell_fullness_logv_called, OP_EQ, 2);

  done:
    stats_n_data_bytes_packaged = 0;
    stats_n_data_cells_packaged = 0;
    UNMOCK(tls_get_write_overhead_ratio);
    UNMOCK(we_are_hibernating);
    UNMOCK(public_server_mode);
    UNMOCK(get_uptime);
    UNMOCK(get_bytes_read);
    UNMOCK(get_bytes_written);
    UNMOCK(logv);
    UNMOCK(server_mode);
    UNMOCK(accounting_is_enabled);
}

static double
status_hb_packaged_cell_fullness_tls_get_write_overhead_ratio(void)
{
  return 1.0;
}

static int
status_hb_packaged_cell_fullness_we_are_hibernating(void)
{
  return 0;
}

static int
status_hb_packaged_cell_fullness_public_server_mode(
                                     const or_options_t *options)
{
  (void)options;

  return 0;
}

static long
status_hb_packaged_cell_fullness_get_uptime(void)
{
  return 0;
}

static uint64_t
status_hb_packaged_cell_fullness_get_bytes_read(void)
{
  return 0;
}

static uint64_t
status_hb_packaged_cell_fullness_get_bytes_written(void)
{
  return 0;
}

static void
status_hb_packaged_cell_fullness_logv(int severity,
    log_domain_mask_t domain, const char *funcname,
    const char *suffix, const char *format, va_list ap)
{
  switch (status_hb_packaged_cell_fullness_logv_called)
  {
    case 0:
      tt_int_op(severity, OP_EQ, LOG_NOTICE);
      tt_u64_op(domain, OP_EQ, LD_HEARTBEAT);
      tt_ptr_op(strstr(funcname, "log_heartbeat"), OP_NE, NULL);
      tt_ptr_op(suffix, OP_EQ, NULL);
      tt_str_op(format, OP_EQ,
          "Heartbeat: Tor's uptime is %s, with %d circuits open. "
          "I've sent %s and received %s.%s");
      tt_str_op(va_arg(ap, char *), OP_EQ, "0:00 hours");  /* uptime */
      tt_int_op(va_arg(ap, int), OP_EQ, 0);  /* count_circuits() */
      tt_str_op(va_arg(ap, char *), OP_EQ, "0 kB");  /* bw_sent */
      tt_str_op(va_arg(ap, char *), OP_EQ, "0 kB");  /* bw_rcvd */
      tt_str_op(va_arg(ap, char *), OP_EQ, "");  /* hibernating */
      break;
    case 1:
      tt_int_op(severity, OP_EQ, LOG_NOTICE);
      tt_u64_op(domain, OP_EQ, LD_HEARTBEAT);
      tt_ptr_op(strstr(funcname, "log_heartbeat"), OP_NE, NULL);
      tt_ptr_op(suffix, OP_EQ, NULL);
      tt_str_op(format, OP_EQ,
          "Average packaged cell fullness: %2.3f%%. "
          "TLS write overhead: %.f%%");
      tt_double_op(fabs(va_arg(ap, double) - 50.0), OP_LE, DBL_EPSILON);
      tt_double_op(fabs(va_arg(ap, double) - 0.0), OP_LE, DBL_EPSILON);
      break;
    default:
      tt_abort_msg("unexpected call to logv()");  // TODO: prettyprint args
      break;
  }

  done:
    status_hb_packaged_cell_fullness_logv_called++;
}

static int
status_hb_packaged_cell_fullness_server_mode(const or_options_t *options)
{
  (void)options;

  return 0;
}

static int
status_hb_packaged_cell_fullness_accounting_is_enabled(
                                             const or_options_t *options)
{
  (void)options;

  return 0;
}

/*
 * Tests that log_heartbeat() correctly logs the TLS write overhead information
 * when the TLS write overhead ratio exceeds 1.
 */

static double status_hb_tls_write_overhead_tls_get_write_overhead_ratio(void);
static int status_hb_tls_write_overhead_we_are_hibernating(void);
static int status_hb_tls_write_overhead_public_server_mode(
               const or_options_t *options);
static long status_hb_tls_write_overhead_get_uptime(void);
static uint64_t status_hb_tls_write_overhead_get_bytes_read(void);
static uint64_t status_hb_tls_write_overhead_get_bytes_written(void);
static void status_hb_tls_write_overhead_logv(
               int severity, log_domain_mask_t domain,
               const char *funcname, const char *suffix,
               const char *format, va_list ap);
static int status_hb_tls_write_overhead_logv_called = 0;
static int status_hb_tls_write_overhead_server_mode(
               const or_options_t *options);
static int status_hb_tls_write_overhead_accounting_is_enabled(
               const or_options_t *options);

static void
test_status_hb_tls_write_overhead(void *arg)
{
  int expected, actual;
  (void)arg;

  MOCK(tls_get_write_overhead_ratio,
       status_hb_tls_write_overhead_tls_get_write_overhead_ratio);
  MOCK(we_are_hibernating,
       status_hb_tls_write_overhead_we_are_hibernating);
  MOCK(public_server_mode,
       status_hb_tls_write_overhead_public_server_mode);
  MOCK(get_uptime,
       status_hb_tls_write_overhead_get_uptime);
  MOCK(get_bytes_read,
       status_hb_tls_write_overhead_get_bytes_read);
  MOCK(get_bytes_written,
       status_hb_tls_write_overhead_get_bytes_written);
  MOCK(logv,
       status_hb_tls_write_overhead_logv);
  MOCK(server_mode,
       status_hb_tls_write_overhead_server_mode);
  MOCK(accounting_is_enabled,
       status_hb_tls_write_overhead_accounting_is_enabled);
  stats_n_data_cells_packaged = 0;
  log_global_min_severity_ = LOG_DEBUG;

  expected = 0;
  actual = log_heartbeat(0);

  tt_int_op(actual, OP_EQ, expected);
  tt_int_op(status_hb_tls_write_overhead_logv_called, OP_EQ, 2);

  done:
    UNMOCK(tls_get_write_overhead_ratio);
    UNMOCK(we_are_hibernating);
    UNMOCK(public_server_mode);
    UNMOCK(get_uptime);
    UNMOCK(get_bytes_read);
    UNMOCK(get_bytes_written);
    UNMOCK(logv);
    UNMOCK(server_mode);
    UNMOCK(accounting_is_enabled);
}

static double
status_hb_tls_write_overhead_tls_get_write_overhead_ratio(void)
{
  return 2.0;
}

static int
status_hb_tls_write_overhead_we_are_hibernating(void)
{
  return 0;
}

static int
status_hb_tls_write_overhead_public_server_mode(const or_options_t *options)
{
  (void)options;

  return 0;
}

static long
status_hb_tls_write_overhead_get_uptime(void)
{
  return 0;
}

static uint64_t
status_hb_tls_write_overhead_get_bytes_read(void)
{
  return 0;
}

static uint64_t
status_hb_tls_write_overhead_get_bytes_written(void)
{
  return 0;
}

static void
status_hb_tls_write_overhead_logv(int severity, log_domain_mask_t domain,
  const char *funcname, const char *suffix, const char *format, va_list ap)
{
  switch (status_hb_tls_write_overhead_logv_called)
  {
    case 0:
      tt_int_op(severity, OP_EQ, LOG_NOTICE);
      tt_u64_op(domain, OP_EQ, LD_HEARTBEAT);
      tt_ptr_op(strstr(funcname, "log_heartbeat"), OP_NE, NULL);
      tt_ptr_op(suffix, OP_EQ, NULL);
      tt_str_op(format, OP_EQ,
          "Heartbeat: Tor's uptime is %s, with %d circuits open. "
          "I've sent %s and received %s.%s");
      tt_str_op(va_arg(ap, char *), OP_EQ, "0:00 hours");  /* uptime */
      tt_int_op(va_arg(ap, int), OP_EQ, 0);  /* count_circuits() */
      tt_str_op(va_arg(ap, char *), OP_EQ, "0 kB");  /* bw_sent */
      tt_str_op(va_arg(ap, char *), OP_EQ, "0 kB");  /* bw_rcvd */
      tt_str_op(va_arg(ap, char *), OP_EQ, "");  /* hibernating */
      break;
    case 1:
      tt_int_op(severity, OP_EQ, LOG_NOTICE);
      tt_u64_op(domain, OP_EQ, LD_HEARTBEAT);
      tt_ptr_op(strstr(funcname, "log_heartbeat"), OP_NE, NULL);
      tt_ptr_op(suffix, OP_EQ, NULL);
      tt_str_op(format, OP_EQ,
          "Average packaged cell fullness: %2.3f%%. "
          "TLS write overhead: %.f%%");
      tt_int_op(fabs(va_arg(ap, double) - 100.0) <= DBL_EPSILON, OP_EQ, 1);
      tt_double_op(fabs(va_arg(ap, double) - 100.0), OP_LE, DBL_EPSILON);
      break;
    default:
      tt_abort_msg("unexpected call to logv()");  // TODO: prettyprint args
      break;
  }

  done:
    status_hb_tls_write_overhead_logv_called++;
}

static int
status_hb_tls_write_overhead_server_mode(const or_options_t *options)
{
  (void)options;

  return 0;
}

static int
status_hb_tls_write_overhead_accounting_is_enabled(const or_options_t *options)
{
  (void)options;

  return 0;
}

struct testcase_t status_tests[] = {
  { "count_circuits", test_status_count_circuits, TT_FORK, NULL, NULL },
  { "secs_to_uptime", test_status_secs_to_uptime, TT_FORK, NULL, NULL },
  { "bytes_to_usage", test_status_bytes_to_usage, TT_FORK, NULL, NULL },
  { "hb_fails", test_status_hb_fails, TT_FORK, NULL, NULL },
  { "hb_simple", test_status_hb_simple, TT_FORK, NULL, NULL },
  { "hb_not_in_consensus", test_status_hb_not_in_consensus,
    TT_FORK, NULL, NULL },
  { "hb_calls_log_accounting", test_status_hb_calls_log_accounting,
    TT_FORK, NULL, NULL },
  { "hb_packaged_cell_fullness", test_status_hb_packaged_cell_fullness,
    TT_FORK, NULL, NULL },
  { "hb_tls_write_overhead", test_status_hb_tls_write_overhead,
    TT_FORK, NULL, NULL },
  END_OF_TESTCASES
};
