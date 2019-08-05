/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2019, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * @file raw_log.h
 * @brief Header for lib/err/raw_log.c
 **/

#ifndef TOR_LIB_ERR_RAW_LOG_H
#define TOR_LIB_ERR_RAW_LOG_H

#include <stdarg.h>
#include <stdbool.h>

void tor_log_raw_ap(int *raw_log_fds, int n_raw_log_fds, bool error_fmt,
                    const char *m, va_list ap);
int tor_log_raw_write(int *raw_log_fds, int n_raw_log_fds, const char *s);

void tor_log_raw_set_granularity(int ms);
int tor_log_raw_get_granularity(void);

int format_hex_number_sigsafe(unsigned long x, char *buf, int max_len);
int format_dec_number_sigsafe(unsigned long x, char *buf, int max_len);

#endif /* !defined(TOR_LIB_ERR_RAW_LOG_H) */
