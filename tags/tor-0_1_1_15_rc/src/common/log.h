/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson. */
/* See LICENSE for licensing information */
/* $Id$ */

/**
 * \file log.h
 *
 * \brief Headers for log.c
 **/

#ifndef __LOG_H
#define LOG_H_ID "$Id$"

#include "../common/compat.h"

#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#define LOG_WARN LOG_WARNING
#if LOG_DEBUG < LOG_ERR
#error "Your syslog.h thinks high numbers are more important.  " \
       "We aren't prepared to deal with that."
#endif
#else
/* XXXX Note: The code was originally written to refer to severities,
 * with 0 being the least severe; while syslog's logging code refers to
 * priorities, with 0 being the most important.  Thus, all our comparisons
 * needed to be reversed when we added syslog support.
 *
 * The upshot of this is that comments about log levels may be messed
 * up: for "maximum severity" read "most severe" and "numerically
 * *lowest* severity".
 */

/** Debug-level severity: for hyper-verbose messages of no interest to
 * anybody but developers. */
#define LOG_DEBUG   7
/** Info-level severity: for messages that appear frequently during normal
 * operation. */
#define LOG_INFO    6
/** Notice-level severity: for messages that appear infrequently
 * during normal operation; that the user will probably care about;
 * and that are not errors.
 */
#define LOG_NOTICE  5
/** Warn-level severity: for messages that only appear when something has gone
 * wrong. */
#define LOG_WARN    4
/** Error-level severity: for messages that only appear when something has gone
 * very wrong, and the Tor process can no longer proceed. */
#define LOG_ERR     3
#endif

/* Logging domains */

/** Catch-all for miscellaneous events and fatal errors. */
#define LD_GENERAL  (1u<<0)
/** The cryptography subsytem. */
#define LD_CRYPTO   (1u<<1)
/** Networking. */
#define LD_NET      (1u<<2)
/** Parsing and acting on our configuration. */
#define LD_CONFIG   (1u<<3)
/** Reading and writing from the filesystem. */
#define LD_FS       (1u<<4)
/** Other servers' (non)compliance with the Tor protocol. */
#define LD_PROTOCOL (1u<<5)
/** Memory management. */
#define LD_MM       (1u<<6)
/** HTTP implementation. */
#define LD_HTTP     (1u<<7)
/** Application (socks) requests. */
#define LD_APP      (1u<<8)
/** Communication via the controller protocol. */
#define LD_CONTROL  (1u<<9)
/** Building, using, and managing circuits. */
#define LD_CIRC     (1u<<10)
/** Hidden services. */
#define LD_REND     (1u<<11)
/** Internal errors in this Tor process. */
#define LD_BUG      (1u<<12)
/** Learning and using information about Tor servers. */
#define LD_DIR      (1u<<13)
/** Learning and using information about Tor servers. */
#define LD_DIRSERV  (1u<<14)
/** Onion routing protocol. */
#define LD_OR       (1u<<15)
/** Generic edge-connection functionality. */
#define LD_EDGE     (1u<<16)
#define LD_EXIT     LD_EDGE
/** Bandwidth accounting. */
#define LD_ACCT     (1u<<17)

typedef void (*log_callback)(int severity, uint32_t domain, const char *msg);

int parse_log_level(const char *level);
const char *log_level_to_string(int level);
void add_stream_log(int severityMin, int severityMax, const char *name,
                    FILE *stream);
int add_file_log(int severityMin, int severityMax, const char *filename);
#ifdef HAVE_SYSLOG_H
int add_syslog_log(int loglevelMin, int loglevelMax);
#endif
int add_callback_log(int loglevelMin, int loglevelMax, log_callback cb);
int get_min_log_level(void);
void switch_logs_debug(void);
void close_logs(void);
void add_temp_log(void);
void close_temp_logs(void);
void rollback_log_changes(void);
void mark_logs_temp(void);
void configure_libevent_logging(void);
void suppress_libevent_log_msg(const char *msg);
void change_callback_log_severity(int loglevelMin, int loglevelMax,
                                  log_callback cb);

/* Outputs a message to stdout */
void _log(int severity, uint32_t domain, const char *format, ...)
  CHECK_PRINTF(3,4);
#define log _log /* hack it so we don't conflict with log() as much */

#ifdef __GNUC__
void _log_fn(int severity, uint32_t domain,
             const char *funcname, const char *format, ...)
  CHECK_PRINTF(4,5);
/** Log a message at level <b>severity</b>, using a pretty-printed version
 * of the current function name. */
#define log_fn(severity, domain, args...)               \
  _log_fn(severity, domain, __PRETTY_FUNCTION__, args)
#define log_debug(domain, args...)                          \
  _log_fn(LOG_DEBUG, domain, __PRETTY_FUNCTION__, args)
#define log_info(domain, args...)                           \
  _log_fn(LOG_INFO, domain, __PRETTY_FUNCTION__, args)
#define log_notice(domain, args...)                         \
  _log_fn(LOG_NOTICE, domain, __PRETTY_FUNCTION__, args)
#define log_warn(domain, args...)                           \
  _log_fn(LOG_WARN, domain, __PRETTY_FUNCTION__, args)
#define log_err(domain, args...)                            \
  _log_fn(LOG_ERR, domain, __PRETTY_FUNCTION__, args)

#else /* ! defined(__GNUC__) */

void _log_fn(int severity, uint32_t domain, const char *format, ...);
void _log_debug(uint32_t domain, const char *format, ...);
void _log_info(uint32_t domain, const char *format, ...);
void _log_notice(uint32_t domain, const char *format, ...);
void _log_warn(uint32_t domain, const char *format, ...);
void _log_err(uint32_t domain, const char *format, ...);

#if defined(_MSC_VER) && _MSC_VER < 1300
/* MSVC 6 and earlier don't have __FUNCTION__, or even __LINE__. */
#define log_fn _log_fn
#define log_debug _log_debug
#define log_info _log_info
#define log_notice _log_notice
#define log_warn _log_warn
#define log_err _log_err
/*
#define debug _debug
#define info _info
#define notice _notice
#define warn _warn
#define err _err
*/
#else
/* We don't have GCC's varargs macros, so use a global variable to pass the
 * function name to log_fn */
extern const char *_log_fn_function_name;
/* We abuse the comma operator here, since we can't use the standard
 * do {...} while (0) trick to wrap this macro, since the macro can't take
 * arguments. */
#define log_fn (_log_fn_function_name=__FUNCTION__),_log_fn
#define log_debug (_log_fn_function_name=__FUNCTION__),_log_debug
#define log_info (_log_fn_function_name=__FUNCTION__),_log_info
#define log_notice (_log_fn_function_name=__FUNCTION__),_log_notice
#define log_warn (_log_fn_function_name=__FUNCTION__),_log_warn
#define log_err (_log_fn_function_name=__FUNCTION__),_log_err
/*
#define debug (_log_fn_function_name=__FUNCTION__),_debug
#define info (_log_fn_function_name=__FUNCTION__),_info
#define notice (_log_fn_function_name=__FUNCTION__),_notice
#define warn (_log_fn_function_name=__FUNCTION__),_warn
#define err (_log_fn_function_name=__FUNCTION__),_err
*/
#endif

#endif /* !GNUC */

# define __LOG_H
#endif

