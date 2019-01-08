/* Copyright (c) 2003-2004, Roger Dingledine
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file addsub.c
 *
 * \brief Helpers for addition and subtraction.
 *
 * Currently limited to non-wrapping (saturating) addition.
 **/

#include "lib/intmath/addsub.h"
#include "lib/cc/compat_compiler.h"

/* A macro that implements a function to safely add two uintn_t's, capping at
 * UINTN_MAX rather than overflow. Does not work for signed types, because
 * (INTN_MAX - b) can underflow. */
#define IMPLEMENT_ADD_NOWRAP(uintn_t, fn_name, UINTN_MAX) \
uintn_t                                                   \
fn_name(uintn_t a, uintn_t b)                             \
{                                                         \
  /* a+b > UINTN_MAX check, without overflow */           \
  if (PREDICT_UNLIKELY(a > UINTN_MAX - b)) {              \
    return UINTN_MAX;                                     \
  } else {                                                \
    return a+b;                                           \
  }                                                       \
}

/* Helper: safely add two uint32_t's, capping at UINT32_MAX rather
 * than overflow */
IMPLEMENT_ADD_NOWRAP(uint32_t, tor_add_u32_nowrap, UINT32_MAX)

/* Helper: safely add two uint64_t's, capping at UINT64_MAX rather
 * than overflow */
IMPLEMENT_ADD_NOWRAP(uint64_t, tor_add_u64_nowrap, UINT64_MAX)
