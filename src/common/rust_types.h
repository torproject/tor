/* Copyright (c) 2017, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file rust_types.h
 * \brief Headers for rust_types.c
 **/

#include "or.h"

#ifndef TOR_RUST_TYPES_H
#define TOR_RUST_TYPES_H

/* This type is used to clearly mark strings that have been allocated in Rust,
 * and therefore strictly need to use the free_rust_str method to free.
 */
typedef char *rust_str_ref_t;

void move_rust_str_to_c_and_free(rust_str_ref_t src, char **dest);

#endif

