/* Copyright (c) 2020, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file hs_ob.h
 * \brief Header file for the specific code for onion balance.
 **/

#ifndef TOR_HS_OB_H
#define TOR_HS_OB_H

#include "hs_service.h"

bool hs_ob_service_is_instance(const hs_service_t *service);

int hs_ob_parse_config_file(hs_service_config_t *config);

struct hs_subcredential_t;
size_t hs_ob_get_subcredentials(const hs_service_config_t *config,
                                struct hs_subcredential_t **subcredentials);

#ifdef HS_OB_PRIVATE

typedef struct ob_options_t {
  /** Magic number to identify the structure in memory. */
  uint32_t magic_;
  /** Master Onion Address(es). */
  struct config_line_t *MasterOnionAddress;
  /** Extra Lines for configuration we might not know. */
  struct config_line_t *ExtraLines;
} ob_options_t;

#endif /* defined(HS_OB_PRIVATE) */

#endif /* !defined(TOR_HS_OB_H) */
