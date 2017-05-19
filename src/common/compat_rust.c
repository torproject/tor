/* Copyright (c) 2017, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file rust_compat.c
 * \brief Rust FFI compatibility functions and helpers. This file is only built
 * if Rust is not used.
 **/

#include "compat_rust.h"
#include "util.h"

/**
 * Free storage pointed to by <b>str</b>, and itself.
 */
void
rust_str_free(rust_str_t str)
{
    char *s = (char *)str;
    tor_free(s);
}

/**
 * Return zero-terminated contained string.
 */
const char *
rust_str_get(const rust_str_t str)
{
    return (const char *)str;
}

/* If we were using Rust, we'd say so on startup. */
rust_str_t
rust_welcome_string(void)
{
    char *s = tor_malloc_zero(1);
    return (rust_str_t)s;
}

