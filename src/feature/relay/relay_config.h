/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2019, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * @file relay_config.h
 * @brief Header for feature/relay/relay_config.c
 **/

#ifndef TOR_FEATURE_RELAY_RELAY_CONFIG_H
#define TOR_FEATURE_RELAY_RELAY_CONFIG_H

typedef struct or_options_t or_options_t;

#ifdef HAVE_MODULE_RELAY

#include "lib/cc/torint.h"
#include "lib/testsupport/testsupport.h"

typedef struct smartlist_t smartlist_t;

int options_validate_relay_mode(const or_options_t *old_options,
                                or_options_t *options,
                                char **msg);

MOCK_DECL(const char*, get_dirportfrontpage, (void));
void relay_config_free_all(void);

uint32_t get_effective_bwrate(const or_options_t *options);
uint32_t get_effective_bwburst(const or_options_t *options);

void warn_nonlocal_ext_orports(const smartlist_t *ports,
                               const char *portname);

int parse_ports_relay(or_options_t *options,
                      char **msg,
                      smartlist_t *ports_out,
                      int *have_low_ports_out);
void update_port_set_relay(or_options_t *options,
                           const smartlist_t *ports);

int options_validate_relay_os(const or_options_t *old_options,
                              or_options_t *options,
                              char **msg);

int options_validate_relay_info(const or_options_t *old_options,
                                or_options_t *options,
                                char **msg);

int options_validate_publish_server(const or_options_t *old_options,
                                    or_options_t *options,
                                    char **msg);

int options_validate_relay_padding(const or_options_t *old_options,
                                   or_options_t *options,
                                   char **msg);

int options_validate_relay_bandwidth(const or_options_t *old_options,
                                     or_options_t *options,
                                     char **msg);

int options_validate_relay_accounting(const or_options_t *old_options,
                                      or_options_t *options,
                                      char **msg);

int options_validate_relay_testing(const or_options_t *old_options,
                                   or_options_t *options,
                                   char **msg);

int options_act_relay(const or_options_t *old_options);
int options_act_relay_accounting(const or_options_t *old_options);
int options_act_relay_bandwidth(const or_options_t *old_options);
int options_act_bridge_stats(const or_options_t *old_options);

int options_act_relay_stats(const or_options_t *old_options,
                            bool *print_notice_out);
void options_act_relay_stats_msg(void);

int options_act_relay_desc(const or_options_t *old_options);
int options_act_relay_dos(const or_options_t *old_options);
int options_act_relay_dir(const or_options_t *old_options);

#ifdef RELAY_CONFIG_PRIVATE

STATIC int check_bridge_distribution_setting(const char *bd);
STATIC int have_enough_mem_for_dircache(const or_options_t *options,
                                        size_t total_mem, char **msg);

#endif

#else

#include "lib/cc/compat_compiler.h"

/** When tor is compiled with the relay module disabled, it can't be
 * configured as a relay or bridge.
 *
 * Always sets ClientOnly to 1.
 *
 * Returns -1 and sets msg to a newly allocated string, if ORPort, DirPort,
 * DirCache, or BridgeRelay are set in options. Otherwise returns 0. */
static inline int
options_validate_relay_mode(const or_options_t *old_options,
                            or_options_t *options,
                            char **msg)
{
  (void)old_options;

  /* Only check the primary options for now, #29211 will disable more
   * options. These ORPort and DirPort checks are too strict, and will
   * reject valid configs that disable ports, like "ORPort 0". */
  if (options->DirCache ||
      options->BridgeRelay ||
      options->ORPort_lines ||
      options->DirPort_lines) {
    /* REJECT() this configuration */
    *msg = tor_strdup("This tor was built with relay mode disabled. "
                      "It can not be configured with an ORPort, a DirPort, "
                      "DirCache 1, or BridgeRelay 1.");
    return -1;
  }

  /* 31851 / 29211: Set this option the correct way */
  options->ClientOnly = 1;

  return 0;
}

#define get_dirportfrontpage() \
  (NULL)
#define relay_config_free_all() \
  STMT_BEGIN STMT_END

#define get_effective_bwrate(options) \
  (((void)(options)),0)
#define get_effective_bwburst(options) \
  (((void)(options)),0)

#define warn_nonlocal_ext_orports(ports, portname) \
  (((void)(ports)),((void)(portname)))

#define parse_ports_relay(options, msg, ports_out, have_low_ports_out) \
  (((void)(options)),((void)(msg)),((void)(ports_out)), \
   ((void)(have_low_ports_out)),0)
#define update_port_set_relay(options, ports) \
  (((void)(options)),((void)(ports)))

#define options_validate_relay_os(old_options, options, msg) \
  (((void)(old_options)),((void)(options)),((void)(msg)),0)
#define options_validate_relay_info(old_options, options, msg) \
  (((void)(old_options)),((void)(options)),((void)(msg)),0)
#define options_validate_publish_server(old_options, options, msg) \
  (((void)(old_options)),((void)(options)),((void)(msg)),0)
#define options_validate_relay_padding(old_options, options, msg) \
  (((void)(old_options)),((void)(options)),((void)(msg)),0)
#define options_validate_relay_bandwidth(old_options, options, msg) \
  (((void)(old_options)),((void)(options)),((void)(msg)),0)
#define options_validate_relay_accounting(old_options, options, msg) \
  (((void)(old_options)),((void)(options)),((void)(msg)),0)
#define options_validate_relay_testing(old_options, options, msg) \
  (((void)(old_options)),((void)(options)),((void)(msg)),0)

#define options_act_relay(old_options) \
  (((void)(old_options)),0)
#define options_act_relay_accounting(old_options) \
  (((void)(old_options)),0)
#define options_act_relay_bandwidth(old_options) \
  (((void)(old_options)),0)
#define options_act_bridge_stats(old_options) \
  (((void)(old_options)),0)

#define options_act_relay_stats(old_options, print_notice_out) \
  (((void)(old_options)),((void)(print_notice_out)),0)
#define options_act_relay_stats_msg() \
  STMT_BEGIN STMT_END

#define options_act_relay_desc(old_options) \
  (((void)(old_options)),0)
#define options_act_relay_dos(old_options) \
  (((void)(old_options)),0)
#define options_act_relay_dir(old_options) \
  (((void)(old_options)),0)

#endif

#endif /* !defined(TOR_FEATURE_RELAY_RELAY_CONFIG_H) */
