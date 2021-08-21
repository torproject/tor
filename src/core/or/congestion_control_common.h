/* Copyright (c) 2019-2021, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file congestion_control_common.h
 * \brief Public APIs for congestion control
 **/

#ifndef TOR_CONGESTION_CONTROL_COMMON_H
#define TOR_CONGESTION_CONTROL_COMMON_H

#include "core/or/crypt_path_st.h"
#include "core/or/circuit_st.h"

typedef struct congestion_control_t congestion_control_t;

/** Wrapper for the free function, set the CC pointer to NULL after free */
#define congestion_control_free(cc) \
    FREE_AND_NULL(congestion_control_t, congestion_control_free_, cc)

void congestion_control_free_(congestion_control_t *cc);

congestion_control_t *congestion_control_new(void);

int congestion_control_dispatch_cc_alg(congestion_control_t *cc,
                                       const circuit_t *circ,
                                       const crypt_path_t *layer_hint);

void congestion_control_note_cell_sent(congestion_control_t *cc,
                                       const circuit_t *circ,
                                       const crypt_path_t *cpath);

bool congestion_control_update_circuit_estimates(congestion_control_t *,
                                                 const circuit_t *,
                                                 const crypt_path_t *);

int congestion_control_get_package_window(const circuit_t *,
                                          const crypt_path_t *);

int sendme_get_inc_count(const circuit_t *, const crypt_path_t *);
bool circuit_sent_cell_for_sendme(const circuit_t *, const crypt_path_t *);
bool is_monotime_clock_reliable(void);

/**
 * Compute an N-count EWMA, aka N-EWMA. N-EWMA is defined as:
 *  EWMA = alpha*value + (1-alpha)*EWMA_prev
 * with alpha = 2/(N+1).
 *
 * This works out to:
 *  EWMA = value*2/(N+1) + EMA_prev*(N-1)/(N+1)
 *       = (value*2 + EWMA_prev*(N-1))/(N+1)
 */
static inline uint64_t
n_count_ewma(uint64_t curr, uint64_t prev, uint64_t N)
{
  if (prev == 0)
    return curr;
  else
    return (2*curr + (N-1)*prev)/(N+1);
}

/* Private section starts. */
#ifdef TOR_CONGESTION_CONTROL_PRIVATE

/*
 * Unit tests declaractions.
 */
#ifdef TOR_UNIT_TESTS

#endif /* defined(TOR_UNIT_TESTS) */

#endif /* defined(TOR_CONGESTION_CONTROL_PRIVATE) */

#endif /* !defined(TOR_CONGESTION_CONTROL_COMMON_H) */
