/* Copyright (c) 2015, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file rendcache.h
 * \brief Header file for rendcache.c
 **/

#ifndef TOR_RENDCACHE_H
#define TOR_RENDCACHE_H

#include "or.h"

/** A cached rendezvous descriptor. */
typedef struct rend_cache_entry_t {
  size_t len; /**< Length of <b>desc</b> */
  time_t last_served; /**< When did we last write this one to somebody?
                       * (HSDir only) */
  char *desc; /**< Service descriptor */
  rend_service_descriptor_t *parsed; /**< Parsed value of 'desc' */
} rend_cache_entry_t;

#endif /* TOR_RENDCACHE_H */
