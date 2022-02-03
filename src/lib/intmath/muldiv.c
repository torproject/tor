/* Copyright (c) 2003-2004, Roger Dingledine
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2019, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file muldiv.c
 *
 * \brief Integer math related to multiplication, division, and rounding.
 **/

#include "lib/intmath/muldiv.h"
#include "lib/err/torerr.h"

#include <stdlib.h>

/** Return the lowest x such that x is at least <b>number</b>, and x modulo
 * <b>divisor</b> == 0.  If no such x can be expressed as an unsigned, return
 * UINT_MAX. Asserts if divisor is zero. */
unsigned
round_to_next_multiple_of(unsigned number, unsigned divisor)
{
  raw_assert(divisor > 0);
  if (UINT_MAX - divisor + 1 < number)
    return UINT_MAX;
  number += divisor - 1;
  number -= number % divisor;
  return number;
}

/** Return the lowest x such that x is at least <b>number</b>, and x modulo
 * <b>divisor</b> == 0. If no such x can be expressed as a uint32_t, return
 * UINT32_MAX. Asserts if divisor is zero. */
uint32_t
round_uint32_to_next_multiple_of(uint32_t number, uint32_t divisor)
{
  raw_assert(divisor > 0);
  if (UINT32_MAX - divisor + 1 < number)
    return UINT32_MAX;

  number += divisor - 1;
  number -= number % divisor;
  return number;
}

/** Return the lowest x such that x is at least <b>number</b>, and x modulo
 * <b>divisor</b> == 0. If no such x can be expressed as a uint64_t, return
 * UINT64_MAX. Asserts if divisor is zero. */
uint64_t
round_uint64_to_next_multiple_of(uint64_t number, uint64_t divisor)
{
  raw_assert(divisor > 0);
  if (UINT64_MAX - divisor + 1 < number)
    return UINT64_MAX;
  number += divisor - 1;
  number -= number % divisor;
  return number;
}

/* Helper: return greatest common divisor of a,b */
static uint64_t
gcd64(uint64_t a, uint64_t b)
{
  while (b) {
    uint64_t t = b;
    b = a % b;
    a = t;
  }
  return a;
}

/* Given a fraction *<b>numer</b> / *<b>denom</b>, simplify it.
 * Requires that the denominator is greater than 0. */
void
simplify_fraction64(uint64_t *numer, uint64_t *denom)
{
  raw_assert(numer);
  raw_assert(denom);
  raw_assert(*denom > 0);

  uint64_t gcd = gcd64(*numer, *denom);
  *numer /= gcd;
  *denom /= gcd;
}

/* Helper: return greatest common divisor of a,b */
static uint32_t
gcd32(uint32_t a, uint32_t b)
{
  while (b) {
    uint32_t t = b;
    b = a % b;
    a = t;
  }
  return a;
}

/* Given a fraction *<b>numer</b> / *<b>denom</b>, simplify it.
 * Requires that the denominator is greater than 0. */
void
simplify_fraction32(uint32_t *numer, uint32_t *denom)
{
  raw_assert(numer);
  raw_assert(denom);
  raw_assert(*denom > 0);

  uint32_t gcd = gcd32(*numer, *denom);
  *numer /= gcd;
  *denom /= gcd;
}
