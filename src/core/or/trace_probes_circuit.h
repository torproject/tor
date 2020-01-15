/* Copyright (c) 2020, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file trace_probes_circuit.c
 * \brief The tracing probes for the circuit subsystem. Currently, only
 *        LTTng-UST probes are available.
 **/

#include "orconfig.h"

/* We only build the following if LTTng instrumentation has been enabled. */
#ifdef USE_TRACING_INSTRUMENTATION_LTTNG

/* The following defines are LTTng-UST specific. */
#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER tor_circuit

#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "./src/core/or/trace_probes_circuit.h"

#if !defined(TOR_TRACE_PROBES_CIRCUIT_H) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define TOR_TRACE_PROBES_CIRCUIT_H

#include <lttng/tracepoint.h>

TRACEPOINT_ENUM(tor_circuit, purpose,
  TP_ENUM_VALUES(
    /* Initializing. */
    ctf_enum_value("<UNSET>", 0)

    /* OR Side. */
    ctf_enum_value("OR", CIRCUIT_PURPOSE_OR)
    ctf_enum_value("OR_INTRO_POINT", CIRCUIT_PURPOSE_INTRO_POINT)
    ctf_enum_value("OR_REND_POINT_WAITING",
                   CIRCUIT_PURPOSE_REND_POINT_WAITING)
    ctf_enum_value("OR_REND_ESTABLISHED", CIRCUIT_PURPOSE_REND_ESTABLISHED)

    /* Client Side. */
    ctf_enum_value("C_GENERAL", CIRCUIT_PURPOSE_C_GENERAL)
    ctf_enum_value("C_INTRODUCING", CIRCUIT_PURPOSE_C_INTRODUCING)
    ctf_enum_value("C_INTRODUCE_ACK_WAIT",
                   CIRCUIT_PURPOSE_C_INTRODUCE_ACK_WAIT)
    ctf_enum_value("C_INTRODUCE_ACKED", CIRCUIT_PURPOSE_C_INTRODUCE_ACKED)
    ctf_enum_value("C_ESTABLISH_REND", CIRCUIT_PURPOSE_C_ESTABLISH_REND)
    ctf_enum_value("C_REND_READY", CIRCUIT_PURPOSE_C_REND_READY)
    ctf_enum_value("C_REND_READY_INTRO_ACKED",
                   CIRCUIT_PURPOSE_C_REND_READY_INTRO_ACKED)
    ctf_enum_value("C_REND_JOINED", CIRCUIT_PURPOSE_C_REND_JOINED)
    ctf_enum_value("C_HSDIR_GET", CIRCUIT_PURPOSE_C_HSDIR_GET)

    /* CBT and Padding. */
    ctf_enum_value("C_MEASURE_TIMEOUT", CIRCUIT_PURPOSE_C_MEASURE_TIMEOUT)
    ctf_enum_value("C_CIRCUIT_PADDING", CIRCUIT_PURPOSE_C_CIRCUIT_PADDING)

    /* Service Side. */
    ctf_enum_value("S_ESTABLISH_INTRO", CIRCUIT_PURPOSE_S_ESTABLISH_INTRO)
    ctf_enum_value("S_INTRO", CIRCUIT_PURPOSE_S_INTRO)
    ctf_enum_value("S_CONNECT_REND", CIRCUIT_PURPOSE_S_CONNECT_REND)
    ctf_enum_value("S_REND_JOINED", CIRCUIT_PURPOSE_S_REND_JOINED)
    ctf_enum_value("S_HSDIR_POST", CIRCUIT_PURPOSE_S_HSDIR_POST)

    /* Misc. */
    ctf_enum_value("TESTING", CIRCUIT_PURPOSE_TESTING)
    ctf_enum_value("CONTROLER", CIRCUIT_PURPOSE_CONTROLLER)
    ctf_enum_value("PATH_BIAS_TESTING", CIRCUIT_PURPOSE_PATH_BIAS_TESTING)

    /* VanGuard */
    ctf_enum_value("HS_VANGUARDS", CIRCUIT_PURPOSE_HS_VANGUARDS)
  )
)

TRACEPOINT_ENUM(tor_circuit, end_reason,
  TP_ENUM_VALUES(
    /* Local reasons. */
    ctf_enum_value("IP_NOW_REDUNDANT", END_CIRC_REASON_IP_NOW_REDUNDANT)
    ctf_enum_value("MEASUREMENT_EXPIRED", END_CIRC_REASON_MEASUREMENT_EXPIRED)
    ctf_enum_value("REASON_NOPATH", END_CIRC_REASON_NOPATH)
    ctf_enum_value("AT_ORIGIN", END_CIRC_AT_ORIGIN)
    ctf_enum_value("NONE", END_CIRC_REASON_NONE)
    ctf_enum_value("TORPROTOCOL", END_CIRC_REASON_TORPROTOCOL)
    ctf_enum_value("INTERNAL", END_CIRC_REASON_INTERNAL)
    ctf_enum_value("REQUESTED", END_CIRC_REASON_REQUESTED)
    ctf_enum_value("HIBERNATING", END_CIRC_REASON_HIBERNATING)
    ctf_enum_value("RESOURCELIMIT", END_CIRC_REASON_RESOURCELIMIT)
    ctf_enum_value("CONNECTFAILED", END_CIRC_REASON_CONNECTFAILED)
    ctf_enum_value("OR_IDENTITY", END_CIRC_REASON_OR_IDENTITY)
    ctf_enum_value("CHANNEL_CLOSED", END_CIRC_REASON_CHANNEL_CLOSED)
    ctf_enum_value("FINISHED", END_CIRC_REASON_FINISHED)
    ctf_enum_value("TIMEOUT", END_CIRC_REASON_TIMEOUT)
    ctf_enum_value("DESTROYED", END_CIRC_REASON_DESTROYED)
    ctf_enum_value("NOSUCHSERVICE", END_CIRC_REASON_NOSUCHSERVICE)

    /* Remote reasons. */
    ctf_enum_value("FLAG_REMOTE", END_CIRC_REASON_FLAG_REMOTE)
    ctf_enum_value("REMOTE_TORPROTOCOL",
             END_CIRC_REASON_FLAG_REMOTE | END_CIRC_REASON_TORPROTOCOL)
    ctf_enum_value("REMOTE_INTERNAL",
             END_CIRC_REASON_FLAG_REMOTE | END_CIRC_REASON_INTERNAL)
    ctf_enum_value("REMOTE_REQUESTED",
             END_CIRC_REASON_FLAG_REMOTE | END_CIRC_REASON_REQUESTED)
    ctf_enum_value("REMOTE_HIBERNATING",
             END_CIRC_REASON_FLAG_REMOTE | END_CIRC_REASON_HIBERNATING)
    ctf_enum_value("REMOTE_RESOURCELIMIT",
             END_CIRC_REASON_FLAG_REMOTE | END_CIRC_REASON_RESOURCELIMIT)
    ctf_enum_value("REMOTE_CONNECTFAILED",
             END_CIRC_REASON_FLAG_REMOTE | END_CIRC_REASON_CONNECTFAILED)
    ctf_enum_value("REMOTE_OR_IDENTITY",
             END_CIRC_REASON_FLAG_REMOTE | END_CIRC_REASON_OR_IDENTITY)
    ctf_enum_value("REMOTE_CHANNEL_CLOSED",
             END_CIRC_REASON_FLAG_REMOTE | END_CIRC_REASON_CHANNEL_CLOSED)
    ctf_enum_value("REMOTE_FINISHED",
             END_CIRC_REASON_FLAG_REMOTE | END_CIRC_REASON_FINISHED)
    ctf_enum_value("REMOTE_TIMEOUT",
             END_CIRC_REASON_FLAG_REMOTE | END_CIRC_REASON_TIMEOUT)
    ctf_enum_value("REMOTE_DESTROYED",
             END_CIRC_REASON_FLAG_REMOTE | END_CIRC_REASON_DESTROYED)
    ctf_enum_value("REMOTE_NOSUCHSERVICE",
             END_CIRC_REASON_FLAG_REMOTE | END_CIRC_REASON_NOSUCHSERVICE)
  )
)

TRACEPOINT_ENUM(tor_circuit, state,
  TP_ENUM_VALUES(
    ctf_enum_value("BUILDING", CIRCUIT_STATE_BUILDING)
    ctf_enum_value("ONIONSKIN_PENDING", CIRCUIT_STATE_ONIONSKIN_PENDING)
    ctf_enum_value("CHAN_WAIT", CIRCUIT_STATE_CHAN_WAIT)
    ctf_enum_value("GUARD_WAIT", CIRCUIT_STATE_GUARD_WAIT)
    ctf_enum_value("OPEN", CIRCUIT_STATE_OPEN)
  )
)

TRACEPOINT_EVENT_CLASS(tor_circuit, origin_circuit_t_class,
  TP_ARGS(const origin_circuit_t *, circ),
  TP_FIELDS(
    ctf_integer(uint32_t, circ_id, circ->global_identifier)
    ctf_enum(tor_circuit, purpose, int, purpose, TO_CIRCUIT(circ)->purpose)
    ctf_enum(tor_circuit, state, int, state, TO_CIRCUIT(circ)->state)
  )
)

TRACEPOINT_EVENT_CLASS(tor_circuit, or_circuit_t_class,
  TP_ARGS(const or_circuit_t *, circ),
  TP_FIELDS(
    ctf_enum(tor_circuit, purpose, int, purpose, TO_CIRCUIT(circ)->purpose)
    ctf_enum(tor_circuit, state, int, state, TO_CIRCUIT(circ)->state)
  )
)

/*
 * Origin circuit events.
 */

TRACEPOINT_EVENT_INSTANCE(tor_circuit, origin_circuit_t_class, new_origin,
  TP_ARGS(const origin_circuit_t *, circ)
)

TRACEPOINT_EVENT_INSTANCE(tor_circuit, origin_circuit_t_class, opened,
  TP_ARGS(const origin_circuit_t *, circ)
)

TRACEPOINT_EVENT_INSTANCE(tor_circuit, origin_circuit_t_class, establish,
  TP_ARGS(const origin_circuit_t *, circ)
)

TRACEPOINT_EVENT_INSTANCE(tor_circuit, origin_circuit_t_class, cannibalized,
  TP_ARGS(const origin_circuit_t *, circ)
)

TRACEPOINT_EVENT_INSTANCE(tor_circuit, origin_circuit_t_class, timeout,
  TP_ARGS(const origin_circuit_t *, circ)
)

TRACEPOINT_EVENT_INSTANCE(tor_circuit, origin_circuit_t_class, idle_timeout,
  TP_ARGS(const origin_circuit_t *, circ)
)

TRACEPOINT_EVENT(tor_circuit, first_onion_skin,
  TP_ARGS(const origin_circuit_t *, circ, const crypt_path_t *, hop),
  TP_FIELDS(
    ctf_integer(uint32_t, circ_id, circ->global_identifier)
    ctf_enum(tor_circuit, purpose, int, purpose, TO_CIRCUIT(circ)->purpose)
    ctf_enum(tor_circuit, state, int, state, TO_CIRCUIT(circ)->state)
    ctf_array_hex(char, fingerprint, hop->extend_info->identity_digest,
                  DIGEST_LEN)
  )
)

TRACEPOINT_EVENT(tor_circuit, intermediate_onion_skin,
  TP_ARGS(const origin_circuit_t *, circ, const crypt_path_t *, hop),
  TP_FIELDS(
    ctf_integer(uint32_t, circ_id, circ->global_identifier)
    ctf_enum(tor_circuit, purpose, int, purpose, TO_CIRCUIT(circ)->purpose)
    ctf_enum(tor_circuit, state, int, state, TO_CIRCUIT(circ)->state)
    ctf_array_hex(char, fingerprint, hop->extend_info->identity_digest,
                  DIGEST_LEN)
  )
)

/*
 * OR circuit events.
 */

TRACEPOINT_EVENT_INSTANCE(tor_circuit, or_circuit_t_class, new_or,
  TP_ARGS(const or_circuit_t *, circ)
)

/*
 * General circuit events.
 */

TRACEPOINT_EVENT(tor_circuit, free,
  TP_ARGS(const circuit_t *, circ),
  TP_FIELDS(
    ctf_integer(uint32_t, circ_id,
                (CIRCUIT_IS_ORIGIN(circ) ?
                 TO_ORIGIN_CIRCUIT(circ)->global_identifier : 0))
    ctf_enum(tor_circuit, purpose, int, purpose, circ->purpose)
    ctf_enum(tor_circuit, state, int, state, circ->state)
  )
)

TRACEPOINT_EVENT(tor_circuit, mark_for_close,
  TP_ARGS(const circuit_t *, circ),
  TP_FIELDS(
    ctf_integer(uint32_t, circ_id,
                (CIRCUIT_IS_ORIGIN(circ) ?
                 TO_ORIGIN_CIRCUIT(circ)->global_identifier : 0))
    ctf_enum(tor_circuit, purpose, int, purpose, circ->purpose)
    ctf_enum(tor_circuit, state, int, state, circ->state)
    ctf_enum(tor_circuit, end_reason, int, close_reason,
             circ->marked_for_close_reason)
    ctf_enum(tor_circuit, end_reason, int, orig_close_reason,
             circ->marked_for_close_orig_reason)
  )
)

TRACEPOINT_EVENT(tor_circuit, change_purpose,
  TP_ARGS(const circuit_t *, circ, int, old_purpose, int, new_purpose),
  TP_FIELDS(
    ctf_integer(uint32_t, circ_id,
                (CIRCUIT_IS_ORIGIN(circ) ?
                 TO_ORIGIN_CIRCUIT(circ)->global_identifier : 0))
    ctf_enum(tor_circuit, state, int, state, circ->state)
    ctf_enum(tor_circuit, purpose, int, purpose, old_purpose)
    ctf_enum(tor_circuit, purpose, int, new, new_purpose)
  )
)

TRACEPOINT_EVENT(tor_circuit, change_state,
  TP_ARGS(const circuit_t *, circ, int, old_state, int, new_state),
  TP_FIELDS(
    ctf_integer(uint32_t, circ_id,
                (CIRCUIT_IS_ORIGIN(circ) ?
                 TO_ORIGIN_CIRCUIT(circ)->global_identifier : 0))
    ctf_enum(tor_circuit, purpose, int, purpose, circ->purpose)
    ctf_enum(tor_circuit, state, int, old, old_state)
    ctf_enum(tor_circuit, state, int, new, new_state)
  )
)

#endif /* TOR_TRACE_PROBES_CIRCUIT_H */

/* Must be include after the probes declaration. */
#include <lttng/tracepoint-event.h>

#endif /* USE_TRACING_INSTRUMENTATION_LTTNG */
