/* Copyright (c) 2017, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file rust_compat.h
 * \brief Headers for rust_compat.c
 **/

#ifndef TOR_RUST_COMPAT_H
#define TOR_RUST_COMPAT_H

#include "torint.h"

/**
 * Strings allocated in Rust must be freed from Rust code again. Let's make
 * it less likely to accidentally mess up and call tor_free() on it, because
 * currently it'll just work but might break at any time.
 */
typedef uintptr_t rust_str_t;

void rust_str_free(rust_str_t);

const char *rust_str_get(const rust_str_t);

rust_str_t rust_welcome_string(void);

#endif /* !defined(TOR_RUST_COMPAT_H) */

