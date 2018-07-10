/* Copyright (c) 2003-2004, Roger Dingledine
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file tm_cvt.h
 * \brief Header for tm_cvt.c
 **/

#ifndef TOR_WALLCLOCK_TM_CVT_H
#define TOR_WALLCLOCK_TM_CVT_H

#include <sys/types.h>

struct tm;
struct tm *tor_localtime_r_msg(const time_t *timep, struct tm *result,
                               char **err_out);
struct tm *tor_gmtime_r_msg(const time_t *timep, struct tm *result,
                            char **err_out);

#endif
