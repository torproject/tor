/* Copyright (c) 2003-2004, Roger Dingledine
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#ifndef TOR_INTMATH_CMP_H
#define TOR_INTMATH_CMP_H

/* Return <b>v</b> if it's between <b>min</b> and <b>max</b>.  Otherwise
 * return <b>min</b> if <b>v</b> is smaller than <b>min</b>, or <b>max</b> if
 * <b>b</b> is larger than <b>max</b>.
 *
 * Requires that <b>min</b> is no more than <b>max</b>. May evaluate any of
 * its arguments more than once! */
#define CLAMP(min,v,max)                        \
  ( ((v) < (min)) ? (min) :                     \
    ((v) > (max)) ? (max) :                     \
    (v) )

#endif /* !defined(TOR_INTMATH_CMP_H) */
