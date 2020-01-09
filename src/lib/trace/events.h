/* Copyright (c) 2017-2020, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file events.h
 * \brief Header file for Tor event tracing.
 **/

#ifndef TOR_LIB_TRACE_EVENTS_H
#define TOR_LIB_TRACE_EVENTS_H

/* XXX: DOCDOC once framework is stable. */

#ifdef HAVE_TRACING

#define tor_trace(subsystem, event_name, ...)           \
  do {                                                  \
    TOR_TRACE_LOG_DEBUG(tor_ ## subsystem, event_name); \
  } while (0)

/* This corresponds to the --enable-tracing-instrumentation-log-debug
 * configure option which maps all tracepoints to a log_debug() statement. */
#include "lib/trace/debug.h"

#else /* !defined(HAVE_TRACING) */

/* Reaching this point, tracing is disabled thus we NOP every tracepoints
 * declaration so we have no execution cost at runtime. */
#define tor_trace(subsystem, name, ...)

#endif /* defined(HAVE_TRACING) */

#endif /* !defined(TOR_LIB_TRACE_EVENTS_H) */
