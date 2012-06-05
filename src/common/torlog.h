/* Copyright (c) 2001, Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2012, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file torlog.h
 *
 * \brief Headers for log.c
 **/

#ifndef _TOR_LOG_H

#include "compat.h"

#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#define LOG_WARN LOG_WARNING
#if LOG_DEBUG < LOG_ERR
#error "Your syslog.h thinks high numbers are more important.  " \
       "We aren't prepared to deal with that."
#endif
#else
/* Note: Syslog's logging code refers to priorities, with 0 being the most
 * important.  Thus, all our comparisons needed to be reversed when we added
 * syslog support.
 *
 * The upshot of this is that comments about log levels may be messed up: for
 * "maximum severity" read "most severe" and "numerically *lowest* severity".
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
/** The cryptography subsystem. */
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
/** Router history */
#define LD_HIST     (1u<<18)
/** OR handshaking */
#define LD_HANDSHAKE (1u<<19)
/** Heartbeat messages */
#define LD_HEARTBEAT (1u<<20)
/** Number of logging domains in the code. */
#define N_LOGGING_DOMAINS 21

/** This log message is not safe to send to a callback-based logger
 * immediately.  Used as a flag, not a log domain. */
#define LD_NOCB (1u<<31)

/** Mask of zero or more log domains, OR'd together. */
typedef uint32_t log_domain_mask_t;

/** Configures which severities are logged for each logging domain for a given
 * log target. */
typedef struct log_severity_list_t {
  /** For each log severity, a bitmask of which domains a given logger is
   * logging. */
  log_domain_mask_t masks[LOG_DEBUG-LOG_ERR+1];
} log_severity_list_t;

#ifdef LOG_PRIVATE
/** Given a severity, yields an index into log_severity_list_t.masks to use
 * for that severity. */
#define SEVERITY_MASK_IDX(sev) ((sev) - LOG_ERR)
#endif

/** Callback type used for add_callback_log. */
typedef void (*log_callback)(int severity, uint32_t domain, const char *msg);

void init_logging(void);
int parse_log_level(const char *level);
const char *log_level_to_string(int level);
int parse_log_severity_config(const char **cfg,
                              log_severity_list_t *severity_out);
void set_log_severity_config(int minSeverity, int maxSeverity,
                             log_severity_list_t *severity_out);
void add_stream_log(const log_severity_list_t *severity, const char *name,
                    int fd);
int add_file_log(const log_severity_list_t *severity, const char *filename);
#ifdef HAVE_SYSLOG_H
int add_syslog_log(const log_severity_list_t *severity);
#endif
int add_callback_log(const log_severity_list_t *severity, log_callback cb);
void logs_set_domain_logging(int enabled);
int get_min_log_level(void);
void switch_logs_debug(void);
void logs_free_all(void);
void add_temp_log(int min_severity);
void close_temp_logs(void);
void rollback_log_changes(void);
void mark_logs_temp(void);
void change_callback_log_severity(int loglevelMin, int loglevelMax,
                                  log_callback cb);
void flush_pending_log_callbacks(void);
void log_set_application_name(const char *name);
void set_log_time_granularity(int granularity_msec);

void tor_log(int severity, log_domain_mask_t domain, const char *format, ...)
  CHECK_PRINTF(3,4);
#define log tor_log /* hack it so we don't conflict with log() as much */

#if defined(__GNUC__) || defined(RUNNING_DOXYGEN)
extern int _log_global_min_severity;

void _log_fn(int severity, log_domain_mask_t domain,
             const char *funcname, const char *format, ...)
  CHECK_PRINTF(4,5);
/** Log a message at level <b>severity</b>, using a pretty-printed version
 * of the current function name. */
#define log_fn(severity, domain, args...)               \
  _log_fn(severity, domain, __PRETTY_FUNCTION__, args)
#define log_debug(domain, args...)                                      \
  STMT_BEGIN                                                            \
    if (PREDICT_UNLIKELY(_log_global_min_severity == LOG_DEBUG))        \
      _log_fn(LOG_DEBUG, domain, __PRETTY_FUNCTION__, args);            \
  STMT_END
#define log_info(domain, args...)                           \
  _log_fn(LOG_INFO, domain, __PRETTY_FUNCTION__, args)
#define log_notice(domain, args...)                         \
  _log_fn(LOG_NOTICE, domain, __PRETTY_FUNCTION__, args)
#define log_warn(domain, args...)                           \
  _log_fn(LOG_WARN, domain, __PRETTY_FUNCTION__, args)
#define log_err(domain, args...)                            \
  _log_fn(LOG_ERR, domain, __PRETTY_FUNCTION__, args)

#else /* ! defined(__GNUC__) */

void _log_fn(int severity, log_domain_mask_t domain, const char *format, ...);
void _log_debug(log_domain_mask_t domain, const char *format, ...);
void _log_info(log_domain_mask_t domain, const char *format, ...);
void _log_notice(log_domain_mask_t domain, const char *format, ...);
void _log_warn(log_domain_mask_t domain, const char *format, ...);
void _log_err(log_domain_mask_t domain, const char *format, ...);

#if defined(_MSC_VER) && _MSC_VER < 1300
/* MSVC 6 and earlier don't have __func__, or even __LINE__. */
#define log_fn _log_fn
#define log_debug _log_debug
#define log_info _log_info
#define log_notice _log_notice
#define log_warn _log_warn
#define log_err _log_err
#else
/* We don't have GCC's varargs macros, so use a global variable to pass the
 * function name to log_fn */
extern const char *_log_fn_function_name;
/* We abuse the comma operator here, since we can't use the standard
 * do {...} while (0) trick to wrap this macro, since the macro can't take
 * arguments. */
#define log_fn (_log_fn_function_name=__func__),_log_fn
#define log_debug (_log_fn_function_name=__func__),_log_debug
#define log_info (_log_fn_function_name=__func__),_log_info
#define log_notice (_log_fn_function_name=__func__),_log_notice
#define log_warn (_log_fn_function_name=__func__),_log_warn
#define log_err (_log_fn_function_name=__func__),_log_err
#endif

#endif /* !GNUC */

# define _TOR_LOG_H
#endif

