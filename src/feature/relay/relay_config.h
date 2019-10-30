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

#include "lib/cc/torint.h"
#include "lib/testsupport/testsupport.h"

typedef struct or_options_t or_options_t;
typedef struct smartlist_t smartlist_t;

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

int options_validate_relay_mode(const or_options_t *old_options,
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

#endif /* !defined(TOR_FEATURE_RELAY_RELAY_CONFIG_H) */
