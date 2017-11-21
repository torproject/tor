/* Copyright (c) 2016-2017, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/*
 * \file protover_rust.c
 * \brief Provide a C wrapper for functions exposed in /src/rust/protover,
 * and safe translation/handling between the Rust/C boundary.
 */

#include "or.h"
#include "protover.h"

#ifdef HAVE_RUST

/* Define for compatibility, used in main.c */
void protover_free_all(void) {}

#endif /* defined(HAVE_RUST) */

