/* Copyright (c) 2020, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file lttng.h
 * \brief Header file for lttng.c.
 **/

#ifndef TOR_TRACE_LTTNG_LTTNG_H
#define TOR_TRACE_LTTNG_LTTNG_H

#ifdef USE_TRACING_INSTRUMENTATION_LTTNG

#include <lttng/tracepoint.h>

/* Map event to an LTTng tracepoint. */
#define TOR_TRACE_LTTNG(subsystem, event_name, args...) \
  tracepoint(tor_##subsystem, event_name, args)

/* Contains the tracepoint event definition. */
#include "providers.h"

#else /* !defined(USE_TRACING_INSTRUMENTATION_LTTNG) */

/* NOP event. */
#define TOR_TRACE_LTTNG(subsystem, event_name, ...)

#endif /* !defined(USE_TRACING_INSTRUMENTATION_LTTNG) */

#endif /* TOR_TRACE_LTTNG_LTTNG_H */

