/* Copyright (c) 2020, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * @file metrics_key.h
 * @brief Contains all metrics key we support.
 **/

#ifndef TOR_LIB_METRICS_METRICS_KEY_H
#define TOR_LIB_METRICS_METRICS_KEY_H

/** Onion service per address + port metrics key type. */
typedef enum {
  /** Number of bytes written from onion service to application. */
  METRICS_HS_APP_WRITE_BYTES,
  /** Number of bytes read from application to onion service. */
  METRICS_HS_APP_READ_BYTES,
} metrics_hs_addr_port_key_t;

/** Onion service per address metrics key type. */
typedef enum {
  /** Number of introduction requests. */
  METRICS_HS_NUM_INTRODUCTIONS,
  /** Number of established rendezsvous. */
  METRICS_HS_NUM_ESTABLISHED_RDV,
  /** Number of rendezsvous circuits created. */
  METRICS_HS_NUM_RDV,
} metrics_hs_addr_key_t;

#endif /* !defined(TOR_LIB_METRICS_METRICS_KEY_H) */
